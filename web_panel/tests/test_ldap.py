"""Tests for the JIT-only LDAP integration and the bulk-sync cleanup migration."""

import hashlib
import sqlite3

import ldap_auth


# ---------- filter building ----------

def test_filter_escapes_injection():
    f = ldap_auth.user_search_filter('admin)(objectClass=*')
    assert '(objectClass=*' not in f.replace('(objectClass=user)', '').replace(
        '(objectClass=inetOrgPerson)', '').replace('(!(objectClass=computer))', '')
    assert '\\29' in f and '\\28' in f  # escaped ) and (


def test_filter_excludes_computers_and_disabled():
    f = ldap_auth.user_search_filter('jdoe')
    assert '(!(objectClass=computer))' in f
    assert 'userAccountControl:1.2.840.113556.1.4.803:=2' in f
    assert '(sAMAccountName=jdoe)' in f


def test_filter_strips_domain_prefix_and_realm():
    f = ldap_auth.user_search_filter('ITERUM\\jdoe')
    assert '(sAMAccountName=jdoe)' in f
    f = ldap_auth.user_search_filter('jdoe@iterum.lv')
    assert '(sAMAccountName=jdoe)' in f
    assert '(userPrincipalName=jdoe@iterum.lv)' in f


# ---------- JIT sync ----------

def test_jit_creates_domain_user_with_unusable_password(app_module, db_path):
    uid = ldap_auth.sync_ldap_user_to_db(
        {'username': 'jdoe', 'email': 'jdoe@x.lv', 'display_name': 'John Doe'}, is_admin=True)
    assert uid
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    assert row['auth_source'] == 'ldap'
    assert row['is_admin'] == 1
    # The stored password must never satisfy local verification
    assert not app_module.verify_password('jdoe', row['password'])
    assert not app_module.verify_password(row['password'], row['password'])
    assert not app_module.verify_password('ldap_jdoe_jdoe@x.lv', row['password'])


def test_jit_refuses_local_account_takeover(app_module, db_path):
    # bootstrap 'admin' is a local account created by init_db
    uid = ldap_auth.sync_ldap_user_to_db(
        {'username': 'admin', 'email': 'evil@x.lv', 'display_name': 'Evil'}, is_admin=True)
    assert uid is None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    conn.close()
    assert row['email'] == 'admin@localhost'  # untouched
    assert (row['auth_source'] or 'local') == 'local'


def test_jit_refreshes_admin_flag_on_relogin(app_module, db_path):
    uid = ldap_auth.sync_ldap_user_to_db(
        {'username': 'jdoe', 'email': 'jdoe@x.lv', 'display_name': 'John'}, is_admin=True)
    uid2 = ldap_auth.sync_ldap_user_to_db(
        {'username': 'jdoe', 'email': 'jdoe@x.lv', 'display_name': 'John'}, is_admin=False)
    assert uid == uid2
    conn = sqlite3.connect(db_path)
    is_admin = conn.execute("SELECT is_admin FROM users WHERE id = ?", (uid,)).fetchone()[0]
    conn.close()
    assert is_admin == 0


# ---------- migration cleanup of retired bulk sync ----------

def _legacy_marker(username, email):
    return hashlib.sha256(f"ldap_{username}_{email}".encode()).hexdigest()


def test_migration_purges_computers_and_marker_rows(app_module, db_path):
    conn = sqlite3.connect(db_path)
    # a computer account and an unreferenced bulk-imported human
    conn.execute("INSERT INTO users (username, password, email, is_admin, status) VALUES (?, ?, ?, 0, 1)",
                 ('PC-042$', _legacy_marker('PC-042$', 'PC-042$@localhost'), 'PC-042$@localhost'))
    conn.execute("INSERT INTO users (username, password, email, is_admin, status) VALUES (?, ?, ?, 0, 1)",
                 ('bulkuser', _legacy_marker('bulkuser', 'bulkuser@x.lv'), 'bulkuser@x.lv'))
    # a bulk-imported human WITH a claimed device -> must be kept but neutralized
    conn.execute("INSERT INTO users (username, password, email, is_admin, status) VALUES (?, ?, ?, 0, 1)",
                 ('keptuser', _legacy_marker('keptuser', 'kept@x.lv'), 'kept@x.lv'))
    kept_id = conn.execute("SELECT id FROM users WHERE username = 'keptuser'").fetchone()[0]
    conn.execute("INSERT INTO devices (id, user_id) VALUES ('123456789', ?)", (kept_id,))
    conn.commit()
    conn.close()

    app_module.init_db()  # re-run migration

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    assert conn.execute("SELECT 1 FROM users WHERE username = 'PC-042$'").fetchone() is None
    assert conn.execute("SELECT 1 FROM users WHERE username = 'bulkuser'").fetchone() is None
    kept = conn.execute("SELECT * FROM users WHERE username = 'keptuser'").fetchone()
    conn.close()
    assert kept is not None
    assert kept['auth_source'] == 'ldap'
    # predictable password neutralized
    assert not app_module.verify_password('ldap_keptuser_kept@x.lv', kept['password'])


def test_migration_keeps_legacy_local_sha256_user(app_module, db_path):
    # a genuine legacy local user (unsalted sha256 of their password) must survive
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO users (username, password, email, is_admin, status) VALUES (?, ?, ?, 0, 1)",
                 ('olduser', hashlib.sha256(b'secret123').hexdigest(), 'old@x.lv'))
    conn.commit()
    conn.close()

    app_module.init_db()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username = 'olduser'").fetchone()
    conn.close()
    assert row is not None
    assert app_module.verify_password('secret123', row['password'])


# ---------- login paths ----------

def test_domain_row_cannot_login_with_local_password(client, app_module, db_path):
    uid = ldap_auth.sync_ldap_user_to_db(
        {'username': 'jdoe', 'email': 'jdoe@x.lv', 'display_name': 'John'}, is_admin=False)
    conn = sqlite3.connect(db_path)
    stored = conn.execute("SELECT password FROM users WHERE id = ?", (uid,)).fetchone()[0]
    conn.close()
    # LDAP is disabled in tests -> /api/login falls to local auth, which must
    # skip domain-managed rows entirely
    r = client.post('/api/login', json={'username': 'jdoe', 'password': stored, 'id': ''})
    assert r.status_code == 200
    assert 'access_token' not in (r.get_json() or {})


def test_local_admin_still_logs_in(client):
    r = client.post('/api/login', json={'username': 'admin', 'password': 'admin123', 'id': ''})
    assert r.status_code == 200
    assert 'access_token' in (r.get_json() or {})
