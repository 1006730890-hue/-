from fastapi.testclient import TestClient


def test_primary_api_contracts(app_modules, monkeypatch):
    from app import agent, llm_client, main

    monkeypatch.setattr(llm_client, "is_available", lambda: False)
    monkeypatch.setattr(agent.llm_client, "is_available", lambda: False)
    client = TestClient(main.app)

    health = client.get("/health")
    overview = client.get("/api/overview")
    green = client.post(
        "/api/chat", json={"message": "查一下余额", "user_token": "guest001"}
    )
    yellow = client.post(
        "/api/chat", json={"message": "给张三转500元", "user_token": "guest001"}
    )
    red = client.post(
        "/api/chat", json={"message": "给李四转2000元", "user_token": "guest001"}
    )

    assert health.status_code == 200
    assert health.json()["status"] == "running"
    assert overview.status_code == 200
    assert "balance" in overview.json()
    assert green.status_code == 200
    assert "reply" in green.json()
    assert yellow.status_code == 200
    assert yellow.json()["confirm"]["risk_level"] == "yellow"
    assert yellow.json()["confirm"]["mfa_required"] is False
    assert red.status_code == 200
    assert red.json()["confirm"]["risk_level"] == "red"
    assert red.json()["confirm"]["mfa_required"] is True
    assert red.json()["confirm"]["demo_mfa_code"]


def test_yellow_confirmation_contract(app_modules, monkeypatch):
    from app import agent, main

    monkeypatch.setattr(agent.llm_client, "is_available", lambda: False)
    client = TestClient(main.app)
    pending = client.post(
        "/api/chat", json={"message": "给张三转500元", "user_token": "guest001"}
    ).json()

    result = client.post(
        "/api/confirm",
        json={
            "action_id": pending["confirm"]["action_id"],
            "approved": True,
            "user_token": "guest001",
        },
    )

    assert result.status_code == 200
    assert result.json()["executed"] is True
    assert result.json()["result"]["transaction_id"]
    task = client.get(
        f"/api/tasks/{pending['task_id']}", params={"token": "guest001"}
    ).json()
    assert task["status"] == "succeeded"
    assert task["nodes"][0]["status"] == "succeeded"


def test_rejected_confirmation_cancels_linked_task(app_modules, monkeypatch):
    from app import agent, main

    monkeypatch.setattr(agent.llm_client, "is_available", lambda: False)
    client = TestClient(main.app)
    pending = client.post(
        "/api/chat", json={"message": "给张三转500元", "user_token": "guest001"}
    ).json()

    result = client.post(
        "/api/confirm",
        json={
            "action_id": pending["confirm"]["action_id"],
            "approved": False,
            "user_token": "guest001",
        },
    )
    task = client.get(
        f"/api/tasks/{pending['task_id']}", params={"token": "guest001"}
    ).json()

    assert result.json()["rejected"] is True
    assert task["status"] == "canceled"
    assert task["nodes"][0]["status"] == "canceled"


def test_red_confirmation_can_retry_after_wrong_mfa(app_modules, monkeypatch):
    from app import agent, main

    monkeypatch.setattr(agent.llm_client, "is_available", lambda: False)
    client = TestClient(main.app)
    pending = client.post(
        "/api/chat", json={"message": "给李四转2000元", "user_token": "guest001"}
    ).json()
    confirmation = pending["confirm"]

    wrong = client.post(
        "/api/confirm",
        json={
            "action_id": confirmation["action_id"],
            "approved": True,
            "mfa_code": "not-the-code",
            "user_token": "guest001",
        },
    ).json()
    correct = client.post(
        "/api/confirm",
        json={
            "action_id": confirmation["action_id"],
            "approved": True,
            "mfa_code": confirmation["demo_mfa_code"],
            "user_token": "guest001",
        },
    ).json()

    assert wrong["mfa_retry"] is True
    assert wrong["attempts_remaining"] == 2
    assert correct["executed"] is True


def test_chat_persists_conversation_and_task(app_modules, monkeypatch):
    from app import agent, main

    monkeypatch.setattr(agent.llm_client, "is_available", lambda: False)
    client = TestClient(main.app)
    response = client.post(
        "/api/chat", json={"message": "查一下余额", "user_token": "guest001"}
    )
    body = response.json()
    tasks = client.get(
        "/api/tasks",
        params={"conversation_id": body["conversation_id"], "token": "guest001"},
    )

    assert body["conversation_id"]
    assert body["task_id"]
    assert tasks.status_code == 200
    assert tasks.json()["tasks"][0]["nodes"][0]["status"] == "succeeded"


def test_task_control_api(app_modules):
    from app import conversation, main

    conversation_id = conversation.ensure(None, 1)
    task_id = conversation.create_task(conversation_id, 1, "需要人工确认的任务")
    client = TestClient(main.app)

    paused = client.post(
        f"/api/tasks/{task_id}/action",
        json={"action": "pause", "user_token": "guest001"},
    )
    resumed = client.post(
        f"/api/tasks/{task_id}/action",
        json={"action": "resume", "user_token": "guest001"},
    )
    detail = client.get(f"/api/tasks/{task_id}", params={"token": "guest001"})

    assert paused.status_code == 200
    assert paused.json()["status"] == "paused"
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "running"
    assert detail.status_code == 200
    assert detail.json()["id"] == task_id
