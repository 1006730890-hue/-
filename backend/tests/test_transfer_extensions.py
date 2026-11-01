from datetime import datetime, timedelta, timezone

import pytest


def _balance(db_module):
    with db_module.db() as conn:
        return conn.execute(
            "SELECT balance FROM accounts WHERE user_id=1"
        ).fetchone()["balance"]


def test_duplicate_recipient_requires_disambiguation(app_modules):
    from app import tools

    result = tools.find_recipients(1, {"name": "张三"})

    assert len(result["candidates"]) == 2
    assert result["requires_disambiguation"] is True
    assert all(candidate["account_masked"].startswith("**** ") for candidate in result["candidates"])
    assert all("account_no" not in candidate for candidate in result["candidates"])


def test_scheduled_transfer_does_not_debit_balance(app_modules):
    from app import tools

    before = _balance(app_modules["db"])
    execute_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    result = tools.schedule_transfer(
        1,
        {"recipient_id": 1, "amount": 288.0, "execute_at": execute_at, "note": "房租"},
    )

    assert result["status"] == "scheduled"
    assert result["requires_pre_execution_review"] is True
    assert result["debited"] is False
    assert _balance(app_modules["db"]) == before

    with app_modules["db"].db() as conn:
        row = conn.execute(
            "SELECT * FROM scheduled_transfers WHERE id=?", (result["schedule_id"],)
        ).fetchone()
    assert row["amount"] == 288.0
    assert row["status"] == "scheduled"
    assert row["execute_at"].endswith("+00:00")


@pytest.mark.parametrize(
    "execute_at",
    [
        "2026-01-01T10:00:00",
        "2020-01-01T10:00:00+08:00",
        "not-a-time",
    ],
)
def test_scheduled_transfer_rejects_invalid_or_unsafe_time(app_modules, execute_at):
    from app import tools

    with pytest.raises(tools.ToolError):
        tools.schedule_transfer(
            1, {"recipient_id": 1, "amount": 100, "execute_at": execute_at}
        )


def test_aa_request_does_not_debit_balance(app_modules):
    from app import tools

    before = _balance(app_modules["db"])
    result = tools.create_aa_request(
        1, {"title": "聚餐", "total_amount": 600, "participant_count": 4}
    )

    assert result["per_person"] == 150.0
    assert result["status"] == "open"
    assert result["debited"] is False
    assert _balance(app_modules["db"]) == before


def test_transfer_extension_risk_levels(app_modules):
    security = app_modules["security"]

    assert security.classify("find_recipients", {}, 1) == security.GREEN
    assert security.classify("schedule_transfer", {}, 1) == security.YELLOW
    assert security.classify("create_aa_request", {}, 1) == security.YELLOW
