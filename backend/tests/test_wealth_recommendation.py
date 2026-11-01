def test_wealth_recommendation_excludes_products_above_user_risk(app_modules):
    from app import tools

    result = tools.recommend_wealth(1, {"amount": 5000, "horizon_months": 12})

    assert result["user_risk"] == "稳健型"
    assert result["risk_ceiling"] == "R2"
    assert result["recommendations"]
    assert {item["risk_level"] for item in result["recommendations"]} <= {"R1", "R2"}
    assert all(item["guaranteed_return"] is False for item in result["recommendations"])
    assert "不代表未来" in result["disclaimer"]
