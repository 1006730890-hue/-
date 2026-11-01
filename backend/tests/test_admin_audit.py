def test_admin_audit_chain_detects_exact_tampered_row(app_modules):
    from app import admin_audit
    from app.admin_seed import seed_admin_data

    seed_admin_data()
    admin_audit.log("adm-observer", "org-hq", "login", "session", None, {}, {"ok": True}, "green", "success")
    admin_audit.log("adm-observer", "org-hq", "dashboard.read", "dashboard", None, {}, {"count": 4}, "green", "success")
    admin_audit.log("adm-observer", "org-hq", "customer.read", "customer", "1", {}, {"error": "forbidden"}, "yellow", "denied")

    assert admin_audit.verify_chain()["valid"] is True

    with app_modules["db"].db() as conn:
        second_id = conn.execute(
            "SELECT id FROM admin_audit_logs ORDER BY id LIMIT 1 OFFSET 1"
        ).fetchone()["id"]
        conn.execute(
            "UPDATE admin_audit_logs SET result=? WHERE id=?",
            ('{"count": 999}', second_id),
        )

    broken = admin_audit.verify_chain()
    assert broken["valid"] is False
    assert broken["broken_at"] == second_id


def test_admin_audit_query_is_read_only(app_modules):
    from app import admin_audit

    assert not hasattr(admin_audit, "delete")
    assert not hasattr(admin_audit, "update")
