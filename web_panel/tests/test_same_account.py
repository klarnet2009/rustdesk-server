"""Same-account passwordless login: server-issued, device-bound, one-time tickets."""


def _user(app_module, name, status=1):
    conn = app_module.get_db()
    cur = conn.execute("INSERT INTO users (username, password, email, is_admin, status) VALUES (?, '', ?, 0, ?)",
                       (name, f"{name}@x", status))
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid


def _own(app_module, device_id, uid):
    conn = app_module.get_db()
    conn.execute("INSERT OR REPLACE INTO devices (id, uuid, user_id, online) VALUES (?, '', ?, 0)", (device_id, uid))
    conn.commit()
    conn.close()


def _bearer(app_module, uid, name):
    return {'Authorization': 'Bearer ' + app_module.create_token(uid, name, False)}


def _ticket(client, app_module, uid, name, target):
    return client.post('/api/same-account/ticket', headers=_bearer(app_module, uid, name), json={'id': target})


def test_owner_gets_ticket_and_it_verifies_once(client, app_module):
    uid = _user(app_module, 'jdoe')
    _own(app_module, '111222333', uid)
    resp = _ticket(client, app_module, uid, 'jdoe', '111222333')
    assert resp.status_code == 200
    ticket = resp.get_json()['ticket']
    ok = client.post('/api/same-account/verify', json={'ticket': ticket, 'id': '111222333'})
    assert ok.status_code == 200
    assert ok.get_json() == {'ok': True, 'name': 'jdoe'}
    replay = client.post('/api/same-account/verify', json={'ticket': ticket, 'id': '111222333'})
    assert replay.get_json()['ok'] is False


def test_non_owner_gets_no_ticket(client, app_module):
    owner = _user(app_module, 'owner')
    other = _user(app_module, 'other')
    _own(app_module, '111222333', owner)
    resp = _ticket(client, app_module, other, 'other', '111222333')
    assert resp.status_code == 403
    assert 'ticket' not in resp.get_json()


def test_ticket_requires_login(client):
    resp = client.post('/api/same-account/ticket', json={'id': '111222333'})
    assert resp.status_code == 401


def test_ticket_is_bound_to_target_device(client, app_module):
    uid = _user(app_module, 'jdoe')
    _own(app_module, '111222333', uid)
    _own(app_module, '444555666', uid)
    ticket = _ticket(client, app_module, uid, 'jdoe', '111222333').get_json()['ticket']
    resp = client.post('/api/same-account/verify', json={'ticket': ticket, 'id': '444555666'})
    assert resp.get_json()['ok'] is False


def test_access_token_is_not_a_ticket(client, app_module):
    uid = _user(app_module, 'jdoe')
    _own(app_module, '111222333', uid)
    jwt_token = app_module.create_token(uid, 'jdoe', False)
    resp = client.post('/api/same-account/verify', json={'ticket': jwt_token, 'id': '111222333'})
    assert resp.get_json()['ok'] is False


def test_expired_ticket_is_rejected(client, app_module, monkeypatch):
    uid = _user(app_module, 'jdoe')
    _own(app_module, '111222333', uid)
    ticket = _ticket(client, app_module, uid, 'jdoe', '111222333').get_json()['ticket']
    real_time = app_module.time.time
    monkeypatch.setattr(app_module.time, 'time', lambda: real_time() + 3600)
    resp = client.post('/api/same-account/verify', json={'ticket': ticket, 'id': '111222333'})
    assert resp.get_json()['ok'] is False


def test_ownership_change_after_issue_is_rejected(client, app_module):
    uid = _user(app_module, 'jdoe')
    other = _user(app_module, 'other')
    _own(app_module, '111222333', uid)
    ticket = _ticket(client, app_module, uid, 'jdoe', '111222333').get_json()['ticket']
    _own(app_module, '111222333', other)
    resp = client.post('/api/same-account/verify', json={'ticket': ticket, 'id': '111222333'})
    assert resp.get_json()['ok'] is False


def test_disabled_user_is_rejected(client, app_module):
    uid = _user(app_module, 'jdoe')
    _own(app_module, '111222333', uid)
    ticket = _ticket(client, app_module, uid, 'jdoe', '111222333').get_json()['ticket']
    conn = app_module.get_db()
    conn.execute("UPDATE users SET status = 0 WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    resp = client.post('/api/same-account/verify', json={'ticket': ticket, 'id': '111222333'})
    assert resp.get_json()['ok'] is False


def test_logout_releases_the_device(client, app_module):
    uid = _user(app_module, 'jdoe')
    _own(app_module, '111222333', uid)
    resp = client.post('/api/logout', headers=_bearer(app_module, uid, 'jdoe'),
                       json={'id': '111222333', 'uuid': ''})
    assert resp.status_code == 200
    conn = app_module.get_db()
    row = conn.execute("SELECT user_id FROM devices WHERE id = ?", ('111222333',)).fetchone()
    conn.close()
    assert row['user_id'] is None
    assert _ticket(client, app_module, uid, 'jdoe', '111222333').status_code == 403


def test_logout_does_not_release_someone_elses_device(client, app_module):
    owner = _user(app_module, 'owner')
    other = _user(app_module, 'other')
    _own(app_module, '111222333', owner)
    client.post('/api/logout', headers=_bearer(app_module, other, 'other'), json={'id': '111222333'})
    conn = app_module.get_db()
    row = conn.execute("SELECT user_id FROM devices WHERE id = ?", ('111222333',)).fetchone()
    conn.close()
    assert row['user_id'] == owner
