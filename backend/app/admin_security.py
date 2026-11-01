"""Compatibility facade for the existing administrator security module."""
from . import admin_auth


def _public(context):
    return {
        "id": context.admin_id,
        "username": context.login_name,
        "display_name": context.display_name,
        "organization_id": context.organization_id,
        "organization_name": context.organization_name,
        "scope_type": context.data_scope,
        "roles": list(context.roles),
        "permissions": sorted(context.permissions),
    }


def login_demo(username):
    result = admin_auth.demo_login(username)
    return {"token": result["token"], "admin": _public(result["admin"])}


def authenticate(token):
    try:
        return _public(admin_auth.authenticate(token))
    except admin_auth.AuthenticationError:
        return None


def disable_admin(admin_id):
    from .db import db
    with db() as conn:
        conn.execute("UPDATE admin_users SET status='disabled' WHERE id=?", (admin_id,))
    admin_auth.revoke_sessions(admin_id)


def visible_organization_ids(admin):
    class Context:
        pass
    context = Context()
    context.data_scope = admin["scope_type"]
    context.organization_id = admin["organization_id"]
    return sorted(admin_auth.visible_org_ids(context))
