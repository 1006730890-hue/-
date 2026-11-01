def test_demo_admin_login_returns_role_scope_and_permissions(app_modules):
    from app import admin_security

    session = admin_security.login_demo("service_nanshan")

    assert session["admin"]["username"] == "service_nanshan"
    assert session["admin"]["scope_type"] == "BRANCH"
    assert session["admin"]["organization_name"] == "南山支行"
    assert "human_reviews.claim" in session["admin"]["permissions"]
    assert "policies.change" not in session["admin"]["permissions"]


def test_admin_session_can_be_disabled_immediately(app_modules):
    from app import admin_security

    session = admin_security.login_demo("observer")
    assert admin_security.authenticate(session["token"])["username"] == "observer"

    admin_security.disable_admin(session["admin"]["id"])

    assert admin_security.authenticate(session["token"]) is None


def test_scope_descendants_include_only_institution_subtree(app_modules):
    from app import admin_security

    session = admin_security.login_demo("service_nanshan")
    visible = admin_security.visible_organization_ids(session["admin"])

    assert visible == ["org-sz-ns"]
    assert admin_security.visible_organization_ids(
        admin_security.login_demo("risk_shenzhen")["admin"]
    ) == ["org-sz", "org-sz-ft", "org-sz-ns"]
import pytest


@pytest.fixture(autouse=True)
def initialized_admins(app_modules):
    from app.admin_seed import seed_admin_data
    seed_admin_data()


