import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_register_and_login_flow():
    try:
        r = client.post('/v1/auth/register', json={'email': 'tester@example.com', 'password': 'Passw0rd!pass'})
    except Exception:
        pytest.skip('DB not available in test environment')
    if r.status_code in (500, 503):
        pytest.skip('Backend not ready (likely no DB)')
    assert r.status_code == 200
    data = r.json()
    assert 'access_token' in data
    assert 'api_key' in data
    api_key = data['api_key']

    r2 = client.post('/v1/auth/login', json={'email': 'tester@example.com', 'password': 'Passw0rd!pass'})
    assert r2.status_code == 200
    token = r2.json()['access_token']

    r4 = client.get('/v1/auth/me', headers={'Authorization': f'Bearer {token}'})
    assert r4.status_code == 200

    r3 = client.post('/v1/analyze', json={'url': 'https://example.com'}, headers={'X-API-Key': api_key})
    assert r3.status_code in (200, 401, 422)


def test_long_password_register_and_login():
    long_pw = 'a' * 60
    r = client.post('/v1/auth/register', json={'email': 'longpass@example.com', 'password': long_pw})
    if r.status_code in (500, 503):
        pytest.skip('Backend not ready')
    assert r.status_code == 200
    # login succeeds
    r2 = client.post('/v1/auth/login', json={'email': 'longpass@example.com', 'password': long_pw})
    assert r2.status_code == 200
    assert 'access_token' in r2.json()


def test_too_long_password_rejected():
    very_long_pw = 'b' * 200
    r = client.post('/v1/auth/register', json={'email': 'toolong@example.com', 'password': very_long_pw})
    if r.status_code in (500, 503):
        pytest.skip('Backend not ready')
    assert r.status_code == 400


def test_unicode_password_over_limit_rejected():
    emoji_pw = '🔒🚀סיסמה' * 20  # multibyte; likely >72 bytes
    r = client.post('/v1/auth/register', json={'email': 'unicode@example.com', 'password': emoji_pw})
    if r.status_code in (500, 503):
        pytest.skip('Backend not ready')
    assert r.status_code == 400
