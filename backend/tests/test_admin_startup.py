import re

from fastapi.testclient import TestClient


def test_startup_serves_admin_assets_and_initializes_login(app_modules):
    from app.main import app

    with TestClient(app) as client:
        page = client.get('/admin/')
        assert page.status_code == 200
        assets = re.findall(r'(?:src|href)="(/admin/assets/[^" ]+)"', page.text)
        assert assets
        for asset in assets:
            assert client.get(asset).status_code == 200
        assert client.get('/').status_code == 200
        login = client.post('/api/admin/auth/demo-login', json={'login_name': 'observer'})
        assert login.status_code == 200
        response = client.get('/api/admin/dashboard', headers={
            'Authorization': 'Bearer ' + login.json()['token']})
        assert response.status_code == 200
        assert response.json()['audit_chain']['valid'] is True
        assert client.get('/api/admin/dashboard').status_code == 401
