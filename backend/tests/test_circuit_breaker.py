import importlib


def test_lock_survives_security_module_reload(app_modules):
    from app import security

    security.note_fail(1, reason="mfa_invalid")
    security.note_fail(1, reason="mfa_invalid")
    security.note_fail(1, reason="mfa_invalid")
    importlib.reload(security)

    state = security.get_lock_state(1)

    assert state.locked is True
    assert state.reason == "mfa_invalid"
    assert state.attempts == 3


def test_green_success_does_not_clear_mfa_failures(app_modules):
    from app import security

    security.note_fail(1, reason="mfa_invalid")
    security.note_success(1, category="green_query")

    state = security.get_lock_state(1)

    assert state.attempts == 1
    assert state.locked is False


def test_successful_mfa_clears_mfa_failures(app_modules):
    from app import security

    security.note_fail(1, reason="mfa_invalid")
    security.note_success(1, category="mfa")

    state = security.get_lock_state(1)

    assert state.attempts == 0
    assert state.locked is False
