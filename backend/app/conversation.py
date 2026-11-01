"""Persistent conversation and lightweight task timeline services."""
import json
import uuid
from datetime import datetime, timezone

from .db import db


class TaskTransitionError(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def ensure(conversation_id, user_id):
    conversation_id = conversation_id or uuid.uuid4().hex
    timestamp = now()
    with db() as conn:
        owner = conn.execute('SELECT user_id FROM conversations WHERE id=?', (conversation_id,)).fetchone()
        if owner and owner['user_id'] != user_id:
            raise ValueError('会话不属于当前用户')
        conn.execute(
            """INSERT INTO conversations(id,user_id,created_at,updated_at)
               VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET updated_at=?""",
            (conversation_id, user_id, timestamp, timestamp, timestamp),
        )
    return conversation_id


def history(conversation_id, user_id, limit=10):
    with db() as conn:
        rows = conn.execute(
            """SELECT role,content FROM conversation_messages
               WHERE conversation_id=? AND conversation_id IN
                 (SELECT id FROM conversations WHERE user_id=?)
               ORDER BY id DESC LIMIT ?""",
            (conversation_id, user_id, limit),
        ).fetchall()
    return [dict(row) for row in reversed(rows)]


def add_message(conversation_id, user_id, role, content):
    with db() as conn:
        conn.execute(
            """INSERT INTO conversation_messages(conversation_id,role,content,created_at)
               SELECT ?,?,?,? WHERE EXISTS
                 (SELECT 1 FROM conversations WHERE id=? AND user_id=?)""",
            (conversation_id, role, content, now(), conversation_id, user_id),
        )


def _validate_nodes(nodes):
    keys = [node["key"] for node in nodes]
    if len(keys) != len(set(keys)):
        raise ValueError("DAG node keys must be unique")
    key_set = set(keys)
    for node in nodes:
        dependencies = node.get("dependencies", [])
        if node["key"] in dependencies or not set(dependencies) <= key_set:
            raise ValueError("DAG contains an invalid dependency")

    visiting = set()
    visited = set()
    graph = {node["key"]: node.get("dependencies", []) for node in nodes}

    def visit(key):
        if key in visiting:
            raise ValueError("DAG contains a cycle")
        if key in visited:
            return
        visiting.add(key)
        for dependency in graph[key]:
            visit(dependency)
        visiting.remove(key)
        visited.add(key)

    for key in keys:
        visit(key)


def create_task(conversation_id, user_id, title, tool_name=None, risk_level=None, nodes=None):
    task_id = uuid.uuid4().hex
    timestamp = now()
    nodes = nodes or [{"key": "request", "tool_name": tool_name, "dependencies": [], "risk_level": risk_level}]
    _validate_nodes(nodes)
    with db() as conn:
        conn.execute(
            "INSERT INTO agent_tasks(id,conversation_id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (task_id, conversation_id, user_id, title, timestamp, timestamp),
        )
        for node in nodes:
            node_id = uuid.uuid4().hex
            conn.execute(
                """INSERT INTO task_nodes(id,task_id,node_key,tool_name,status,dependencies,risk_level,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    node_id, task_id, node["key"], node.get("tool_name"),
                    "running" if not node.get("dependencies") else "planned",
                    json.dumps(node.get("dependencies", []), ensure_ascii=False),
                    node.get("risk_level", risk_level), timestamp, timestamp,
                ),
            )
    return task_id


def _task_from_row(conn, row):
    task = dict(row)
    task["nodes"] = []
    for node in conn.execute(
        "SELECT * FROM task_nodes WHERE task_id=? ORDER BY created_at, rowid",
        (task["id"],),
    ).fetchall():
        item = dict(node)
        item["dependencies"] = json.loads(item["dependencies"] or "[]")
        task["nodes"].append(item)
    return task


def get_task(task_id, user_id):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM agent_tasks WHERE id=? AND user_id=?", (task_id, user_id)
        ).fetchone()
        return _task_from_row(conn, row) if row else None


def list_tasks(conversation_id, user_id, limit=20):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM agent_tasks WHERE conversation_id=? AND user_id=? ORDER BY created_at DESC LIMIT ?",
            (conversation_id, user_id, limit),
        ).fetchall()
        result = []
        for row in rows:
            result.append(_task_from_row(conn, row))
        return result


TASK_TRANSITIONS = {
    "pause": ({"running", "waiting_confirmation", "waiting_mfa"}, "paused"),
    "resume": ({"paused"}, "running"),
    "cancel": ({"running", "paused", "waiting_confirmation", "waiting_mfa"}, "canceled"),
    "human_review": ({"running", "paused", "waiting_confirmation", "waiting_mfa"}, "human_review"),
}


def transition_task(task_id, user_id, action, reason=None):
    if action not in TASK_TRANSITIONS:
        raise TaskTransitionError("不支持的任务操作")
    allowed, target = TASK_TRANSITIONS[action]
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM agent_tasks WHERE id=? AND user_id=?", (task_id, user_id)
        ).fetchone()
        if not row:
            raise TaskTransitionError("任务不存在")
        if row["status"] not in allowed:
            raise TaskTransitionError(f"任务状态 {row['status']} 不能执行 {action}")
        timestamp = now()
        conn.execute(
            "UPDATE agent_tasks SET status=?,review_reason=?,updated_at=? WHERE id=?",
            (target, reason if action == "human_review" else None, timestamp, task_id),
        )
        if target in {"paused", "canceled", "human_review"}:
            node_status = "canceled" if target == "canceled" else target
            conn.execute(
                "UPDATE task_nodes SET status=?,updated_at=? WHERE task_id=? AND status IN ('planned','running')",
                (node_status, timestamp, task_id),
            )
        elif target == "running":
            conn.execute(
                "UPDATE task_nodes SET status='running',updated_at=? WHERE task_id=? AND status='paused' AND dependencies='[]'",
                (timestamp, task_id),
            )
    return get_task(task_id, user_id)


def update_latest_task(conversation_id, user_id, status, result=None):
    with db() as conn:
        task = conn.execute(
            "SELECT id FROM agent_tasks WHERE conversation_id=? AND user_id=? ORDER BY created_at DESC LIMIT 1",
            (conversation_id, user_id),
        ).fetchone()
        if not task:
            return
        timestamp = now()
        conn.execute("UPDATE agent_tasks SET status=?,updated_at=? WHERE id=?", (status, timestamp, task["id"]))
        conn.execute(
            "UPDATE task_nodes SET status=?,result=?,updated_at=? WHERE task_id=? AND status='running'",
            ("succeeded" if status == "succeeded" else status, json.dumps(result, ensure_ascii=False) if result else None, timestamp, task["id"]),
        )


def bind_pending_action(action_id, task_id, user_id):
    with db() as conn:
        conn.execute(
            """UPDATE pending_actions SET task_id=?
               WHERE id=? AND user_id=? AND status='pending'""",
            (task_id, action_id, user_id),
        )


def finalize_pending_task(action_id, user_id, result):
    if result.get("mfa_retry"):
        return
    with db() as conn:
        action = conn.execute(
            "SELECT task_id FROM pending_actions WHERE id=? AND user_id=?",
            (action_id, user_id),
        ).fetchone()
        if not action or not action["task_id"]:
            return
        if result.get("executed"):
            status, node_status = "succeeded", "succeeded"
        elif result.get("rejected"):
            status, node_status = "canceled", "canceled"
        else:
            status, node_status = "failed", "failed"
        timestamp = now()
        payload = json.dumps(result, ensure_ascii=False)
        conn.execute(
            "UPDATE agent_tasks SET status=?,updated_at=? WHERE id=? AND user_id=?",
            (status, timestamp, action["task_id"], user_id),
        )
        conn.execute(
            """UPDATE task_nodes SET status=?,result=?,updated_at=?
               WHERE task_id=? AND status IN ('running','waiting_confirmation','waiting_mfa')""",
            (node_status, payload, timestamp, action["task_id"]),
        )


def update_task(task_id,user_id,status,result=None):
    with db() as conn:
        conn.execute('UPDATE agent_tasks SET status=?,updated_at=? WHERE id=? AND user_id=?',(status,now(),task_id,user_id))
        conn.execute("UPDATE task_nodes SET status=?,result=?,updated_at=? WHERE task_id=? AND status='running'",
                     ('succeeded' if status == 'succeeded' else status,json.dumps(result,ensure_ascii=False),now(),task_id))
