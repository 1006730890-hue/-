from fastapi.testclient import TestClient


def _login(client, login_name):
    response = client.post("/api/admin/auth/demo-login", json={"login_name": login_name})
    assert response.status_code == 200
    return response.json()["token"]


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_demo_accounts_login_me_and_dashboard(app_modules):
    from app.admin_seed import seed_admin_data
    from app import main

    seed_admin_data()
    client = TestClient(main.app)
    accounts = client.get("/api/admin/auth/demo-accounts")
    token = _login(client, "observer")
    me = client.get("/api/admin/me", headers=_headers(token))
    dashboard = client.get("/api/admin/dashboard", headers=_headers(token))

    assert len(accounts.json()["accounts"]) == 7
    assert me.json()["login_name"] == "observer"
    assert "dashboard.read" in me.json()["permissions"]
    assert dashboard.status_code == 200
    assert dashboard.json()["services"]["api"] == "online"
    assert "customers" not in dashboard.json()


def test_customer_token_and_role_without_permission_are_rejected(app_modules):
    from app.admin_seed import seed_admin_data
    from app import main

    seed_admin_data()
    client = TestClient(main.app)
    assert client.get("/api/admin/dashboard").status_code == 401
    assert client.get(
        "/api/admin/dashboard", headers=_headers("guest001")
    ).status_code == 401
    observer = _login(client, "observer")
    assert client.get(
        "/api/admin/reviews", headers=_headers(observer)
    ).status_code == 403


def test_institution_scope_and_review_claim_conflict(app_modules):
    from app.admin_seed import seed_admin_data
    from app import main

    seed_admin_data()
    client = TestClient(main.app)
    service = _login(client, "service_nanshan")
    reviews = client.get("/api/admin/reviews", headers=_headers(service)).json()["items"]
    assert {item["id"] for item in reviews} == {"review-ns"}

    claimed = client.post(
        "/api/admin/reviews/review-ns/claim", headers=_headers(service)
    )
    conflict = client.post(
        "/api/admin/reviews/review-ns/claim", headers=_headers(service)
    )
    assert claimed.status_code == 200
    assert conflict.status_code == 409


def test_maker_cannot_approve_own_request(app_modules):
    from app.admin_seed import seed_admin_data
    from app import main

    seed_admin_data()
    client = TestClient(main.app)
    security = _login(client, "security_hq")
    created = client.post(
        "/api/admin/approvals",
        headers=_headers(security),
        json={"request_type": "policy_change", "reason": "比赛演示变更",
              "payload": {"key": "daily_yellow_limit", "value": 1200}},
    )
    assert created.status_code == 200
    request_id = created.json()["id"]
    own = client.post(
        f"/api/admin/approvals/{request_id}/decision",
        headers=_headers(security), json={"approved": True, "reason": "同意"},
    )
    assert own.status_code == 403 or own.status_code == 409

    reviewer = _login(client, "reviewer_hq")
    approved = client.post(
        f"/api/admin/approvals/{request_id}/decision",
        headers=_headers(reviewer), json={"approved": True, "reason": "复核通过"},
    )
    duplicate = client.post(
        f"/api/admin/approvals/{request_id}/decision",
        headers=_headers(reviewer), json={"approved": True, "reason": "再次提交"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "EXECUTED"
    assert duplicate.status_code == 409


def test_admin_audit_verification_api(app_modules):
    from app.admin_seed import seed_admin_data
    from app import main

    seed_admin_data()
    client = TestClient(main.app)
    auditor = _login(client, "auditor_hq")
    result = client.get("/api/admin/audit/verify", headers=_headers(auditor))
    assert result.status_code == 200
    assert result.json()["valid"] is True
