import pytest


def _task(app_modules):
    from app import conversation

    conversation_id = conversation.ensure(None, 1)
    task_id = conversation.create_task(
        conversation_id,
        1,
        "转账并分析账单",
        nodes=[
            {"key": "bill", "tool_name": "monthly_bill", "dependencies": []},
            {"key": "risk", "tool_name": "transfer", "dependencies": []},
            {"key": "confirm", "tool_name": None, "dependencies": ["risk"]},
            {"key": "execute", "tool_name": "transfer", "dependencies": ["confirm"]},
        ],
    )
    return conversation_id, task_id


def test_dag_persists_dependencies(app_modules):
    from app import conversation

    conversation_id, task_id = _task(app_modules)
    task = conversation.get_task(task_id, 1)

    assert task["conversation_id"] == conversation_id
    assert len(task["nodes"]) == 4
    assert task["nodes"][3]["dependencies"] == ["confirm"]


def test_task_can_pause_and_resume(app_modules):
    from app import conversation

    _, task_id = _task(app_modules)
    paused = conversation.transition_task(task_id, 1, "pause")
    resumed = conversation.transition_task(task_id, 1, "resume")

    assert paused["status"] == "paused"
    assert resumed["status"] == "running"


def test_canceled_task_cannot_resume(app_modules):
    from app import conversation

    _, task_id = _task(app_modules)
    conversation.transition_task(task_id, 1, "cancel")

    with pytest.raises(conversation.TaskTransitionError):
        conversation.transition_task(task_id, 1, "resume")


def test_task_can_enter_human_review(app_modules):
    from app import conversation

    _, task_id = _task(app_modules)
    task = conversation.transition_task(
        task_id, 1, "human_review", reason="收款人身份无法消歧"
    )

    assert task["status"] == "human_review"
    assert task["review_reason"] == "收款人身份无法消歧"
