from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def seeded_admins(app_modules):
    from app.admin_seed import seed_admin_data

    seed_admin_data()
    return app_modules["db"]


def test_demo_login_persists_only_token_digest(seeded_admins):
    from app import admin_auth

    session = admin_auth.demo_login("service_nanshan")
    context = admin_auth.authenticate(session["token"])

    assert context.login_name == "service_nanshan"
    assert "human_reviews.claim" in context.permissions
    with seeded_admins.db() as conn:
        row = conn.execute("SELECT token_hash FROM admin_sessions").fetchone()
    assert row["token_hash"] != session["token"]
    assert len(row["token_hash"]) == 64


def test_disabled_and_expired_admin_sessions_are_rejected(seeded_admins):
    from app import admin_auth

    session = admin_auth.demo_login("observer")
    with seeded_admins.db() as conn:
        conn.execute("UPDATE admin_users SET status='disabled' WHERE login_name='observer'")
    with pytest.raises(admin_auth.AuthenticationError):
        admin_auth.authenticate(session["token"])

    session = admin_auth.demo_login("service_nanshan")
    with seeded_admins.db() as conn:
        conn.execute(
            "UPDATE admin_sessions SET expires_at=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),),
        )
    with pytest.raises(admin_auth.AuthenticationError):
        admin_auth.authenticate(session["token"])


def test_rbac_and_nanshan_scope_are_enforced(seeded_admins):
    from app import admin_auth

    observer = admin_auth.authenticate(admin_auth.demo_login("observer")["token"])
    service = admin_auth.authenticate(admin_auth.demo_login("service_nanshan")["token"])

    with pytest.raises(admin_auth.PermissionDenied):
        admin_auth.require_permission(observer, "customer_summary.read")
    assert admin_auth.visible_org_ids(service) == {"org-sz-ns"}
    assert "org-sz-ft" not in admin_auth.visible_org_ids(service)
    assert "org-gz" not in admin_auth.visible_org_ids(service)
