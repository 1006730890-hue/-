"""Administrator authentication, RBAC, and organization data scope."""
import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .db import db


class AuthenticationError(ValueError):
    pass


class PermissionDenied(ValueError):
    pass


@dataclass(frozen=True)
class AdminContext:
    admin_id: str
    login_name: str
    display_name: str
    organization_id: str
    organization_name: str
    data_scope: str
    roles: tuple[str, ...]
    permissions: frozenset[str]


def _now():
    return datetime.now(timezone.utc)


def _digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _context(conn, admin_id):
    user = conn.execute(
        """SELECT u.*,o.name organization_name FROM admin_users u
           JOIN organizations o ON o.id=u.organization_id WHERE u.id=?""",
        (admin_id,),
    ).fetchone()
    if not user or user["status"] != "enabled":
        raise AuthenticationError("管理员账号不可用")
    roles = conn.execute(
        """SELECT r.code FROM admin_roles r JOIN admin_user_roles ur ON ur.role_id=r.id
           WHERE ur.admin_id=? ORDER BY r.code""", (admin_id,),
    ).fetchall()
    permissions = conn.execute(
        """SELECT DISTINCT p.code FROM admin_permissions p
           JOIN admin_role_permissions rp ON rp.permission_id=p.id
           JOIN admin_user_roles ur ON ur.role_id=rp.role_id WHERE ur.admin_id=?""",
        (admin_id,),
    ).fetchall()
    return AdminContext(
        user["id"], user["login_name"], user["display_name"],
        user["organization_id"], user["organization_name"], user["data_scope"],
        tuple(row["code"] for row in roles),
        frozenset(row["code"] for row in permissions),
    )


def demo_login(login_name, ttl_hours=8):
    token = secrets.token_urlsafe(32)
    now = _now()
    with db() as conn:
        user = conn.execute(
            "SELECT id,status FROM admin_users WHERE login_name=?", (login_name,)
        ).fetchone()
        if not user or user["status"] != "enabled":
            raise AuthenticationError("管理员账号不存在或已停用")
        context = _context(conn, user["id"])
        conn.execute(
            """INSERT INTO admin_sessions(
                   id,admin_id,token_hash,created_at,expires_at,last_seen_at
               ) VALUES(?,?,?,?,?,?)""",
            (uuid.uuid4().hex, user["id"], _digest(token), now.isoformat(),
             (now + timedelta(hours=ttl_hours)).isoformat(), now.isoformat()),
        )
    return {"token": token, "expires_at": (now + timedelta(hours=ttl_hours)).isoformat(),
            "admin": context}


def authenticate(token):
    if not token:
        raise AuthenticationError("管理员会话缺失")
    now = _now()
    with db() as conn:
        session = conn.execute(
            "SELECT * FROM admin_sessions WHERE token_hash=?", (_digest(token),)
        ).fetchone()
        if not session or session["revoked_at"]:
            raise AuthenticationError("管理员会话无效")
        if datetime.fromisoformat(session["expires_at"]) <= now:
            raise AuthenticationError("管理员会话已过期")
        context = _context(conn, session["admin_id"])
        conn.execute("UPDATE admin_sessions SET last_seen_at=? WHERE id=?",
                     (now.isoformat(), session["id"]))
        return context


def require_permission(context, permission):
    if permission not in context.permissions:
        raise PermissionDenied(f"缺少权限：{permission}")


def visible_org_ids(context):
    if context.data_scope == "GLOBAL":
        with db() as conn:
            return {row["id"] for row in conn.execute("SELECT id FROM organizations")}
    if context.data_scope in {"SELF", "BRANCH"}:
        return {context.organization_id}
    if context.data_scope == "SUBTREE":
        result = {context.organization_id}
        frontier = [context.organization_id]
        with db() as conn:
            while frontier:
                rows = conn.execute(
                    f"SELECT id FROM organizations WHERE parent_id IN ({','.join('?' for _ in frontier)})",
                    frontier,
                ).fetchall()
                frontier = [row["id"] for row in rows if row["id"] not in result]
                result.update(frontier)
        return result
    return {context.organization_id}


def revoke_sessions(admin_id):
    with db() as conn:
        conn.execute(
            "UPDATE admin_sessions SET revoked_at=? WHERE admin_id=? AND revoked_at IS NULL",
            (_now().isoformat(), admin_id),
        )


def logout(token):
    with db() as conn:
        conn.execute(
            "UPDATE admin_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
            (_now().isoformat(), _digest(token)),
        )
