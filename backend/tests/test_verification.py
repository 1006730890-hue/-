import importlib
import json
from datetime import datetime, timezone


def _pending_action(db, action_id=1):
    with db.db() as conn:
        conn.execute(
            """INSERT INTO pending_actions(
                   id,user_id,tool_name,args,risk_level,status,created_at,mfa_required
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (
                action_id,
                1,
                "transfer",
                json.dumps({"to_name": "张三", "amount": 2000}, ensure_ascii=False),
                "red",
                "pending",
                datetime.now(timezone.utc).isoformat(),
                1,
            ),
        )


def test_mfa_survives_module_reload(app_modules):
    from app import verification

    _pending_action(app_modules["db"])
    code = verification.issue(action_id=1, ttl_seconds=120)
    importlib.reload(verification)

    result = verification.verify(action_id=1, code=code)

    assert result.ok is True
    assert result.code == "verified"


def test_missing_persisted_challenge_never_accepts_nonempty_code(app_modules):
    from app import verification

    result = verification.verify(action_id=9999, code="123456")

    assert result.ok is False
    assert result.code == "challenge_missing"


def test_mfa_is_single_use(app_modules):
    from app import verification

    _pending_action(app_modules["db"])
    code = verification.issue(action_id=1, ttl_seconds=120)

    assert verification.verify(1, code).ok is True
    second = verification.verify(1, code)
    assert second.ok is False
    assert second.code == "challenge_missing"


def test_wrong_mfa_increments_attempts(app_modules):
    from app import verification

    _pending_action(app_modules["db"])
    verification.issue(action_id=1, ttl_seconds=120)

    result = verification.verify(1, "not-the-code")

    assert result.ok is False
    assert result.code == "invalid_code"
    assert result.attempts_remaining == 2


def test_expired_mfa_is_rejected(app_modules):
    from app import verification

    _pending_action(app_modules["db"])
    code = verification.issue(action_id=1, ttl_seconds=-1)

    result = verification.verify(1, code)

    assert result.ok is False
    assert result.code == "challenge_expired"
