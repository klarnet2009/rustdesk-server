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
    import server as server_mod
    importlib.reload(server_mod)
    server_mod.init_db()
    return server_mod


@pytest.fixture()
def client(app_module):
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()
