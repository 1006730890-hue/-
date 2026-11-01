import pytest


def test_wealth_purchase_blocks_risk_mismatch(app_modules):
    from app import tools

    with pytest.raises(tools.ToolError, match="风险不匹配"):
        tools.purchase_wealth(
            1, {"product_name": "沪深300指数增强", "amount": 1000}
        )


def test_wealth_purchase_allows_matching_product(app_modules):
    from app import tools

    result = tools.purchase_wealth(
        1, {"product_name": "稳健添利", "amount": 1000}
    )

    assert result["ok"] is True
    assert result["risk_level"] == "R2"
