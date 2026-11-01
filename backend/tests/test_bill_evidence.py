def test_anomaly_contains_explanation_and_evidence(app_modules):
    from app import tools

    result = tools.detect_anomaly(1, {})

    assert result["threshold"] > 0
    assert result["anomalies"]
    anomaly = result["anomalies"][0]
    assert anomaly["reason"]
    assert anomaly["baseline"] == result["avg_txn"]
    assert anomaly["evidence_id"] == f"txn-{anomaly['id']}"
