from fastapi.testclient import TestClient


def test_normal_mode_requires_real_login_and_logout_revokes_session(app_modules,monkeypatch):
    from app import main,config,customer_auth
    monkeypatch.setattr(config.settings,'DEMO_MODE',False)
    customer_auth.initialize()
    access = (app_modules['db_path'].parent/'initial-customer-access.txt').read_text(encoding='utf-8')
    password = access.split('初始密码：',1)[1].splitlines()[0]
    client = TestClient(main.app)
    assert client.get('/api/overview').status_code == 401
    assert client.get('/api/admin/dashboard').status_code == 403
    response = client.post('/api/auth/login',json={'login_name':'张伟','password':password})
    assert response.status_code == 200
    token = response.json()['token']
    headers = {'Authorization':'Bearer '+token}
    assert client.get('/api/overview',headers=headers).status_code == 200
    assert client.post('/api/auth/logout',headers=headers).status_code == 200
    assert client.get('/api/overview',headers=headers).status_code == 401


def test_wrong_password_attempts_are_persistently_limited(app_modules):
    from app import customer_auth
    customer_auth.initialize()
    for _ in range(5):
        assert not customer_auth.login('张伟','incorrect')['ok']
    assert customer_auth.login('张伟','incorrect')['code'] == 'login_locked'


def test_totp_matches_standard_test_vector():
    import base64
    from app.verification import _totp
    secret = base64.b32encode(b'12345678901234567890').decode()
    assert _totp(secret,1) == '287082'
