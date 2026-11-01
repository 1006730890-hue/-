"""Append-only, hash-linked administrator audit records."""
import hashlib
import json
from datetime import datetime, timezone

from .db import db


GENESIS = "0" * 64


def _canonical(row):
    fields = {
        key: row[key] for key in (
            "ts", "admin_id", "organization_id", "action", "resource_type",
            "resource_id", "params", "result", "risk_level", "outcome"
        )
    }
    return json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(previous, row):
    return hashlib.sha256(f"{previous}\n{_canonical(row)}".encode("utf-8")).hexdigest()


def log(admin_id, organization_id, action, resource_type, resource_id,
        params, result, risk_level="green", outcome="success"):
    row = {
        "ts": datetime.now(timezone.utc).isoformat(), "admin_id": admin_id,
        "organization_id": organization_id, "action": action,
        "resource_type": resource_type, "resource_id": resource_id,
        "params": json.dumps(params, ensure_ascii=False, sort_keys=True),
        "result": json.dumps(result, ensure_ascii=False, sort_keys=True),
        "risk_level": risk_level, "outcome": outcome,
    }
    with db() as conn:
        head = conn.execute(
            "SELECT entry_hash FROM admin_audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = head["entry_hash"] if head else GENESIS
        digest = _hash(previous, row)
        cur = conn.execute(
            """INSERT INTO admin_audit_logs(
                   ts,admin_id,organization_id,action,resource_type,resource_id,
                   params,result,risk_level,outcome,previous_hash,entry_hash
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (*row.values(), previous, digest),
        )
        return cur.lastrowid


def list_logs(limit=100, admin_id=None):
    sql, args = "SELECT * FROM admin_audit_logs", []
    if admin_id:
        sql += " WHERE admin_id=?"
        args.append(admin_id)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(min(max(int(limit), 1), 500))
    with db() as conn:
        return [dict(row) for row in conn.execute(sql, args).fetchall()]


def verify_chain():
    previous = GENESIS
    with db() as conn:
        rows = conn.execute("SELECT * FROM admin_audit_logs ORDER BY id").fetchall()
    for row in rows:
        expected = _hash(previous, row)
        if row["previous_hash"] != previous or row["entry_hash"] != expected:
            return {"valid": False, "checked": max(0, row["id"] - 1),
                    "broken_at": row["id"], "head_hash": previous}
        previous = row["entry_hash"]
    return {"valid": True, "checked": len(rows), "broken_at": None,
            "head_hash": previous}
