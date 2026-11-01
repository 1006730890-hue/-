def test_audit_chain_verifies_and_detects_tampering(app_modules):
    from app import audit

    audit.log(1, "agent", "policy", {"amount": 500}, {"allowed": True}, "yellow")
    audit.log(1, "user", "confirm", {"approved": True}, {"ok": True}, "yellow")

    verified = audit.verify_chain()
    assert verified["valid"] is True
    assert verified["checked"] == 2
    assert len(verified["head_hash"]) == 64

    with app_modules["db"].db() as conn:
        conn.execute("UPDATE audit_logs SET result=? WHERE id=1", ('{"ok": false}',))

    broken = audit.verify_chain()
    assert broken["valid"] is False
    assert broken["broken_at"] == 1


def test_audit_chain_backfills_legacy_rows(app_modules):
    from app import audit

    with app_modules["db"].db() as conn:
        conn.execute(
            """INSERT INTO audit_logs(
                   ts,user_id,actor,action,params,result,risk_level,decision_chain
               ) VALUES(?,?,?,?,?,?,?,?)""",
            ("2026-01-01T00:00:00", 1, "agent", "legacy", "{}", "{}", "green", "[]"),
        )

    result = audit.verify_chain()

    assert result["valid"] is True
    assert result["checked"] == 1
