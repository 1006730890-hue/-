from fastapi.testclient import TestClient


def test_twelve_month_report_has_trend_categories_and_evidence(app_modules):
    from app import tools

    result = tools.spending_report(1, {"months": 12})

    assert len(result["monthly_trend"]) == 12
    assert result["total_expense"] > 0
    assert result["category_ranking"][0]["share"] > 0
    assert result["month_over_month_pct"] is not None
    assert all(item["evidence_id"].startswith("txn-") for item in result["evidence"])


def test_spending_report_csv_export(app_modules):
    from app import main

    client = TestClient(main.app)
    response = client.get(
        "/api/reports/spending.csv", params={"months": 12, "token": "guest001"}
    )

    assert response.status_code == 200
    assert response.content.startswith("\ufeff月份".encode("utf-8"))
    assert "餐饮" in response.content.decode("utf-8-sig")
    assert "attachment" in response.headers["content-disposition"]
