import json
from datetime import datetime, timedelta, timezone


def _pending_transfer(monkeypatch, amount=500):
    from app import agent

    monkeypatch.setattr(agent.llm_client, "is_available", lambda: False)
    return agent.run(1, f"给张三转{amount}元", [])


def _balance(db):
    with db.db() as conn:
        return conn.execute(
            "SELECT balance FROM accounts WHERE user_id=1"
        ).fetchone()["balance"]


def test_repeated_confirmation_executes_transfer_once(app_modules, monkeypatch):
    from app import agent

    pending = _pending_transfer(monkeypatch)
    before = _balance(app_modules["db"])

    first = agent.confirm_action(1, pending["confirm"]["action_id"], True)
    second = agent.confirm_action(1, pending["confirm"]["action_id"], True)

    with app_modules["db"].db() as conn:
        count = conn.execute(
            """SELECT COUNT(*) AS c FROM transactions
               WHERE user_id=1 AND txn_type='transfer_out' AND amount=500"""
        ).fetchone()["c"]

    assert first["executed"] is True
    assert second["executed"] is False
    assert second["code"] == "already_processed"
    assert count == 1
    assert _balance(app_modules["db"]) == before - 500


def test_expired_confirmation_does_not_change_balance(app_modules, monkeypatch):
    from app import agent

    pending = _pending_transfer(monkeypatch)
    action_id = pending["confirm"]["action_id"]
    before = _balance(app_modules["db"])
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with app_modules["db"].db() as conn:
        conn.execute(
            "UPDATE pending_actions SET expires_at=? WHERE id=?",
            (expired, action_id),
        )

    result = agent.confirm_action(1, action_id, True)

    assert result["executed"] is False
    assert result["code"] == "confirmation_expired"
    assert _balance(app_modules["db"]) == before


def test_tampered_confirmation_does_not_change_balance(app_modules, monkeypatch):
    from app import agent

    pending = _pending_transfer(monkeypatch)
    action_id = pending["confirm"]["action_id"]
    before = _balance(app_modules["db"])
    with app_modules["db"].db() as conn:
        conn.execute(
            "UPDATE pending_actions SET args=? WHERE id=?",
            (json.dumps({"to_name": "攻击者", "amount": 500}), action_id),
        )

    result = agent.confirm_action(1, action_id, True)

    assert result["executed"] is False
    assert result["code"] == "confirmation_tampered"
    assert _balance(app_modules["db"]) == before
