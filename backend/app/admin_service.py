"""Scoped administrator operations and maker-checker approvals."""
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from . import admin_audit, admin_auth, audit, llm_client
from .db import db


class NotFound(ValueError): pass
class Conflict(ValueError): pass
class InvalidRequest(ValueError): pass


def _now(): return datetime.now(timezone.utc)
def _canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
def _hash(value): return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def dashboard(ctx):
    admin_auth.require_permission(ctx, "dashboard.read")
    orgs = admin_auth.visible_org_ids(ctx)
    placeholders = ",".join("?" for _ in orgs)
    with db() as conn:
        tasks = conn.execute("SELECT status,COUNT(*) n FROM agent_tasks GROUP BY status").fetchall()
        risks = conn.execute(f"SELECT severity,COUNT(*) n FROM risk_events WHERE organization_id IN ({placeholders}) GROUP BY severity", tuple(orgs)).fetchall()
        approvals = conn.execute("SELECT COUNT(*) n FROM admin_approval_requests WHERE status='PENDING'").fetchone()["n"]
        reviews = conn.execute(f"SELECT COUNT(*) n FROM human_review_queue WHERE organization_id IN ({placeholders}) AND status IN ('open','claimed')", tuple(orgs)).fetchone()["n"]
    result = {"services": {"api": "online", "database": "online", "ollama": "online" if llm_client.is_available() else "degraded"},
              "model": getattr(llm_client.settings, "LLM_MODEL", "local") if hasattr(llm_client, "settings") else "local",
              "tasks": {row["status"]: row["n"] for row in tasks},
              "risks": {row["severity"]: row["n"] for row in risks},
              "pending_approvals": approvals, "open_reviews": reviews,
              "audit_chain": admin_audit.verify_chain()}
    admin_audit.log(ctx.admin_id, ctx.organization_id, "dashboard.read", "dashboard", None, {}, {"ok": True})
    return result


def list_reviews(ctx):
    admin_auth.require_permission(ctx, "human_reviews.read")
    orgs = admin_auth.visible_org_ids(ctx)
    sql = f"SELECT * FROM human_review_queue WHERE organization_id IN ({','.join('?' for _ in orgs)}) ORDER BY created_at DESC"
    with db() as conn: return [dict(row) for row in conn.execute(sql, tuple(orgs)).fetchall()]


def claim_review(ctx, review_id):
    admin_auth.require_permission(ctx, "human_reviews.claim")
    if not review_id in {item["id"] for item in list_reviews(ctx)}: raise NotFound("人工任务不存在")
    now = _now().isoformat()
    with db() as conn:
        changed = conn.execute("UPDATE human_review_queue SET status='claimed',claimed_by=?,claimed_at=?,updated_at=? WHERE id=? AND status='open'", (ctx.admin_id, now, now, review_id))
    if changed.rowcount != 1: raise Conflict("任务已被其他管理员认领")
    admin_audit.log(ctx.admin_id, ctx.organization_id, "review.claim", "human_review", review_id, {}, {"status": "claimed"}, "yellow")
    return {"id": review_id, "status": "claimed", "claimed_by": ctx.admin_id}


def list_risks(ctx):
    admin_auth.require_permission(ctx, "risk_events.read")
    orgs = admin_auth.visible_org_ids(ctx)
    with db() as conn:
        return [dict(r) for r in conn.execute(f"SELECT * FROM risk_events WHERE organization_id IN ({','.join('?' for _ in orgs)}) ORDER BY created_at DESC", tuple(orgs)).fetchall()]


def list_approvals(ctx):
    admin_auth.require_permission(ctx, "approvals.read")
    with db() as conn: return [dict(r) for r in conn.execute("SELECT * FROM admin_approval_requests ORDER BY created_at DESC").fetchall()]


def create_approval(ctx, request_type, payload, reason):
    admin_auth.require_permission(ctx, "approvals.create")
    allowed = {"policy_change", "admin_disable", "role_change", "customer_unlock", "sensitive_export"}
    if request_type not in allowed: raise InvalidRequest("不支持的审批类型")
    now, request_id = _now(), uuid.uuid4().hex
    canonical = _canonical(payload)
    with db() as conn:
        conn.execute("""INSERT INTO admin_approval_requests(id,request_type,requester_id,organization_id,payload,payload_hash,reason,status,created_at,expires_at)
                        VALUES(?,?,?,?,?,?,?,'PENDING',?,?)""", (request_id, request_type, ctx.admin_id, ctx.organization_id, canonical, _hash(payload), reason, now.isoformat(), (now + timedelta(minutes=5)).isoformat()))
    admin_audit.log(ctx.admin_id, ctx.organization_id, "approval.create", "approval", request_id, payload, {"status": "PENDING"}, "red")
    return get_approval(request_id)


def get_approval(request_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM admin_approval_requests WHERE id=?", (request_id,)).fetchone()
    if not row: raise NotFound("审批不存在")
    result = dict(row); result["payload"] = json.loads(result["payload"]); return result


def decide_approval(ctx, request_id, approved, reason):
    admin_auth.require_permission(ctx, "approvals.decide")
    request = get_approval(request_id)
    if request["requester_id"] == ctx.admin_id: raise Conflict("经办人与复核人不能是同一人")
    if request["status"] != "PENDING": raise Conflict("审批已处理")
    if datetime.fromisoformat(request["expires_at"]) <= _now(): raise Conflict("审批已过期")
    if _hash(request["payload"]) != request["payload_hash"]: raise Conflict("审批参数校验失败")
    now = _now().isoformat()
    if not approved:
        with db() as conn: conn.execute("UPDATE admin_approval_requests SET status='REJECTED',approver_id=?,decision_reason=?,decided_at=? WHERE id=? AND status='PENDING'", (ctx.admin_id, reason, now, request_id))
        return get_approval(request_id)
    with db() as conn:
        claimed = conn.execute("UPDATE admin_approval_requests SET status='APPROVING',approver_id=?,decision_reason=?,decided_at=? WHERE id=? AND status='PENDING'", (ctx.admin_id, reason, now, request_id))
        if claimed.rowcount != 1: raise Conflict("审批已处理")
        if request["request_type"] == "admin_disable":
            target = request["payload"].get("admin_id"); conn.execute("UPDATE admin_users SET status='disabled' WHERE id=?", (target,))
        result = {"executed": True, "type": request["request_type"]}
        conn.execute("UPDATE admin_approval_requests SET status='EXECUTED',executed_at=?,result=? WHERE id=? AND status='APPROVING'", (now, _canonical(result), request_id))
    if request["request_type"] == "admin_disable": admin_auth.revoke_sessions(request["payload"].get("admin_id"))
    admin_audit.log(ctx.admin_id, ctx.organization_id, "approval.execute", "approval", request_id, {}, result, "red")
    return get_approval(request_id)
