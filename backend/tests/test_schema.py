def test_security_schema_is_available(app_modules):
    db = app_modules["db"]
    with db.db() as conn:
        pending = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(pending_actions)").fetchall()
        }
        breaker = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='security_states'"
        ).fetchone()

    assert {
        "action_token",
        "payload_hash",
        "expires_at",
        "mfa_hash",
        "mfa_salt",
        "mfa_expires_at",
        "mfa_attempts",
        "executed_at",
    } <= pending
    assert breaker is not None
