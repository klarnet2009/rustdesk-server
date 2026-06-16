# Modules Documentation

## 1. server.py (Web Panel Entry & Core Logic)
* **Purpose**: Hosts the Flask routing, API endpoints, SQLite DB creation/migration, and embedded HTML templates.
* **Key Functions**:
  - `init_db()`: Initializes tables (`users`, `devices`, `logs`, `connections`, `settings`) in the SQLite database.
  - `get_db()`: Helper returning a thread-safe connection to the SQLite database.
  - `token_required(f)`: Decodes and validates JWT bearer tokens for API authorization.
  - `web_login_required(f)`: Session guard for UI pages.
  - `admin_required(f)`: Decorator protecting administrative routes from regular users.
  - `render_page(template, **kwargs)`: Custom HTML compiler extracting blocks and rendering them inside `BASE_HTML`.
  - `web_save_ldap()` / `api_test_ldap()`: LDAP configuration managers.
  - `web_my_devices()`: Renders the personalized "My Devices" panel.
  - `web_save_device_password()`: Updates the unattended connection password for a device.
  - `web_claim_device()` / `web_unclaim_device()`: Manages device-to-user mappings.
  - `get_id_server()`: Resolves the active ID Server IP.
  - `/api/global-settings`: REST API returning centralized global client settings.
  - `/api/login-sso`: SSO endpoint validating incoming base64-encoded Negotiate Kerberos tokens via `pyspnego`.
* **Internal Logic**: Runs a production-ready WSGI app via Gunicorn or debug mode on Flask. Maps SQLite records to tabular data.

## 2. ldap_auth.py (AD / LDAP Authentication Integration)
* **Purpose**: Connects to domain controllers to authorize users via active directory.
* **Key Functions**:
  - `discover_base_dn(server, user, password)`: Connects to a domain controller and auto-discovers the Root Base DN.
  - `authenticate_ldap(username, password)`: Verifies credentials against Active Directory using LDAP simple bind.
* **Relationships**: Imported directly by `server.py` when validating log-in requests and testing configurations from the Settings panel.

## 3. Client Update Manager
* **Purpose**: Coordinates forced automatic update checks, downloads, and installations on client startup.
* **Components**:
  - **Rust Client Updater** (`src/updater.rs`, `src/common.rs`, `src/flutter_ffi.rs`): Performs version check queries, downloads update files (EXE/MSI), and launches elevated silent installer processes via `update_to(file)`.
  - **Flutter Dialogs & Managers** (`lib/services/update_manager.dart`, `lib/widgets/update_dialog.dart`, `lib/main.dart`): Handles global update listeners, initializes update routines on app start, and presents a non-dismissible "Updating..." progress screen.
  - **Android Update Service** (`UpdateService.kt`): Queries the releases API, parses assets for ARM/universal APK matching, downloads packages, and invokes native package installation intents.

## 4. flutter_ffi.rs (Kerberos Windows SSPI Bridge)
* **Purpose**: Performs passwordless Kerberos SSO token generation on Windows clients.
* **Key Functions**:
  - `main_get_sso_token()`: Dynamically loads `Secur32.dll`, generates security credentials, calls `InitializeSecurityContextW` to negotiate a ticket for the server's SPN, and returns the base64-encoded ticket.
* **Relationships**: Bound as a Flutter FFI function, called automatically by `tryKerberosSso` in `user_model.dart` on application startup when running on Windows.
