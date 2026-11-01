ADMIN_TABLES = {
    "organizations",
    "admin_users",
    "admin_roles",
    "admin_permissions",
    "admin_user_roles",
    "admin_role_permissions",
    "admin_sessions",
    "admin_approval_requests",
    "admin_audit_logs",
    "risk_events",
    "human_review_queue",
}


def test_admin_schema_and_seed_are_idempotent(app_modules):
    from app import admin_seed

    database = app_modules["db"]
    with database.db() as conn:
        existing = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        before_balance = conn.execute(
            "SELECT balance FROM accounts WHERE user_id=1"
        ).fetchone()["balance"]

    assert ADMIN_TABLES <= existing

    admin_seed.seed_admin_data()
    admin_seed.seed_admin_data()

    with database.db() as conn:
        organizations = conn.execute(
            "SELECT code,parent_id FROM organizations ORDER BY code"
        ).fetchall()
        admins = conn.execute(
            "SELECT login_name,status FROM admin_users ORDER BY login_name"
        ).fetchall()
        after_balance = conn.execute(
            "SELECT balance FROM accounts WHERE user_id=1"
        ).fetchone()["balance"]

    assert {row["code"] for row in organizations} == {
        "HQ", "SZ", "SZ-NS", "SZ-FT", "GZ", "GZ-TH", "GZ-YX"
    }
    assert len(admins) == 7
    assert all(row["status"] == "enabled" for row in admins)
    assert after_balance == before_balance
