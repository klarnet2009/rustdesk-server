import base64


def _neg(header_value):
    return {'Authorization': 'Negotiate ' + header_value}


def test_simulation_token_is_rejected(client):
    # The retired dev bypass: a base64 "TOCKEN_SIMULATION_admin" must NOT yield a token.
    payload = base64.b64encode(b'TOCKEN_SIMULATION_admin').decode()
    resp = client.post('/api/login-sso', headers=_neg(payload))
    assert resp.status_code != 200
    body = resp.get_json(silent=True) or {}
    assert 'access_token' not in body


def test_login_sso_challenges_without_auth(client):
    resp = client.post('/api/login-sso')
    assert resp.status_code == 401
    assert resp.headers.get('WWW-Authenticate') == 'Negotiate'


import types
import base64 as _b64
import pytest
import sso_kerberos


def test_validate_returns_principal(monkeypatch):
    class FakeCtx:
        complete = True
        client_principal = 'jdoe@EXAMPLE.LOCAL'
        def step(self, token):
            assert token == b'rawtoken'
            return None
    captured = {}
    def fake_server(hostname, service):
        captured['hostname'] = hostname
        captured['service'] = service
        return FakeCtx()
    monkeypatch.setattr(sso_kerberos, 'spnego', types.SimpleNamespace(server=fake_server), raising=False)
    monkeypatch.setattr(sso_kerberos, 'SPNEGO_AVAILABLE', True, raising=False)
    principal = sso_kerberos.validate_negotiate_token(_b64.b64encode(b'rawtoken').decode(), 'HTTP/rustdesk.test.local')
    assert principal == 'jdoe@EXAMPLE.LOCAL'
    assert captured == {'hostname': 'rustdesk.test.local', 'service': 'HTTP'}


def test_validate_incomplete_handshake_raises(monkeypatch):
    class FakeCtx:
        complete = False
        client_principal = None
        def step(self, token):
            return b'continue'
    monkeypatch.setattr(sso_kerberos, 'spnego', types.SimpleNamespace(server=lambda hostname, service: FakeCtx()), raising=False)
    monkeypatch.setattr(sso_kerberos, 'SPNEGO_AVAILABLE', True, raising=False)
    with pytest.raises(sso_kerberos.SsoError):
        sso_kerberos.validate_negotiate_token(_b64.b64encode(b'x').decode(), 'HTTP/rustdesk.test.local')


def test_validate_bad_base64_raises(monkeypatch):
    monkeypatch.setattr(sso_kerberos, 'SPNEGO_AVAILABLE', True, raising=False)
    with pytest.raises(sso_kerberos.SsoError):
        sso_kerberos.validate_negotiate_token('!!!not base64!!!', 'HTTP/rustdesk.test.local')
