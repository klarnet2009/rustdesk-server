# Modules Documentation

## 1. server.py (Web Panel Entry & Core Logic)
* **Purpose**: Hosts the Flask routing, API endpoints, SQLite DB creation/migration, and embedded HTML templates.
* **Key Functions**:
  - `init_db()`: Initializes tables (`users`, `devices`, `logs`, `connections`, `settings`) in the SQLite database.
  - `get_db()`: Helper returning a thread-safe connection to the SQLite database.
  - `token_required(f)`: Decodes and validates JWT bearer tokens for API authorization.
  - `web_login_required(f)`: Session guard for UI pages.
  - `render_page(template, **kwargs)`: Custom HTML compiler extracting blocks and rendering them inside `BASE_HTML`.
  - `web_save_ldap()` / `api_test_ldap()`: LDAP configuration managers.
* **Internal Logic**: Runs a production-ready WSGI app via Gunicorn or debug mode on Flask. Maps SQLite records to tabular data.

## 2. ldap_auth.py (AD / LDAP Authentication Integration)
* **Purpose**: Connects to domain controllers to authorize users via active directory.
* **Key Functions**:
  - `discover_base_dn(server, user, password)`: Connects to a domain controller and auto-discovers the Root Base DN.
  - `authenticate_ldap(username, password)`: Verifies credentials against Active Directory using LDAP simple bind.
* **Relationships**: Imported directly by `server.py` when validating log-in requests and testing configurations from the Settings panel.
