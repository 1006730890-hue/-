import pytest


INVALID_AMOUNTS = [None, True, False, "", "abc", [], {}, "NaN", "Infinity",
                   float("nan"), float("inf"), float("-inf"), 0, -1,
                   "0.001", "500.001", "1e999"]


@pytest.mark.parametrize("amount", INVALID_AMOUNTS)
def test_invalid_transfer_amount_is_denied_by_policy(app_modules, amount):
    decision = app_modules["security"].decide("transfer", {"amount": amount}, 1)
    assert decision.allowed is False
    assert decision.code == "invalid_amount"


@pytest.mark.parametrize("amount", INVALID_AMOUNTS)
def test_invalid_transfer_amount_cannot_modify_ledger(app_modules, amount):
    from app import tools

    def snapshot():
        with app_modules["db"].db() as conn:
            balance = conn.execute("SELECT balance FROM accounts WHERE user_id=1").fetchone()["balance"]
            count = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
            return balance, count

    before = snapshot()
    with pytest.raises(tools.ToolError):
        tools.transfer(1, {"to_name": "张三", "amount": amount})
    assert snapshot() == before


@pytest.mark.parametrize("amount", ["0.01", "500.00", 1000, "1e2"])
def test_valid_transfer_amount_is_accepted(app_modules, amount):
    assert app_modules["security"].decide("transfer", {"amount": amount}, 1).allowed


def test_transfer_is_yellow_at_cumulative_limit(app_modules):
    security = app_modules["security"]
    assert security.classify("transfer", {"amount": 1000}, 1) == "yellow"


def test_transfer_is_red_above_cumulative_limit(app_modules):
    security = app_modules["security"]
    assert security.classify("transfer", {"amount": 1000.01}, 1) == "red"


def test_transfer_above_daily_hard_limit_is_blocked(app_modules):
    security = app_modules["security"]
    decision = security.decide("transfer", {"amount": 50000.01}, 1)
    assert decision.allowed is False
    assert decision.code == "daily_transfer_limit_exceeded"


def test_direct_tool_call_cannot_bypass_hard_limit(app_modules):
    from app import tools

    with pytest.raises(tools.ToolError, match="单日转账上限"):
        tools.transfer(1, {"to_name": "张三", "amount": 50000.01})
