import os
import tempfile
import pytest


@pytest.fixture()
def db_path(monkeypatch):
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    monkeypatch.setenv('RUSTDESK_DB_PATH', path)
    monkeypatch.setenv('SSO_SPN', 'HTTP/rustdesk.test.local')
    yield path
    os.remove(path)


@pytest.fixture()
def app_module(db_path):
    # Import after RUSTDESK_DB_PATH is set so init_db() writes to the temp DB.
    import importlib
    # Point ldap_auth's module-level DB_PATH at the temp DB for the duration of
    # the test so LDAP writes (e.g. sync_ldap_user_to_db) hit the isolated temp
    # DB rather than the real rustdesk.db captured at collection-time import.
    # Restored on teardown so db_path-only tests keep their original binding.
    import ldap_auth as ldap_mod
    old_ldap_db = ldap_mod.DB_PATH
    ldap_mod.DB_PATH = db_path
    import server as server_mod
    importlib.reload(server_mod)
    server_mod.init_db()
    yield server_mod
    ldap_mod.DB_PATH = old_ldap_db


@pytest.fixture()
def client(app_module):
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()
