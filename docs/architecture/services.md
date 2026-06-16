# Services Documentation

## 1. hbbs (ID Server)
* **Purpose**: Coordinates client signaling and broker services.
* **Responsibilities**:
  - Direct connection coordinate discovery.
  - Active session logging.
  - Public/private key encryption validation for client requests.
* **Dependencies**: SQLite database (`rustdesk.db`).
* **Protocol**: Custom UDP & TCP protocol on port `21115` (signal), `21116` (id), and `21118` (web socket).

## 2. hbbr (Relay Server)
* **Purpose**: Relays session data between clients when direct P2P connections fail.
* **Responsibilities**:
  - High-bandwidth data forwarding.
  - Session key verification.
* **Dependencies**: None.
* **Protocol**: Custom TCP on port `21117` and `21119` (web socket).

## 3. Web Management Panel
* **Purpose**: Provides administrative control and system monitoring.
* **Responsibilities**:
  - Managing user roles (Administrators vs regular Users).
  - Monitoring active and historic device registrations.
  - Auditing connection and file transfer logs.
  - Auto-discovering and configuring Active Directory/LDAP credentials.
  - Centralizing and enforcing client configuration profiles (Global Settings) across all client devices.
* **Dependencies**: Python 3, Flask, SQLite (`rustdesk.db`), and optionally `ldap3` for Active Directory integration.
* **APIs Exposed**:
  - `/api/devices`: List/update devices.
  - `/api/admin/users`: CRUD operations on console users.
  - `/api/ldap/test`: Auto-discovery connection check endpoint.
  - `/api/login`: Form-based authentication endpoint that maps the connecting device ID to the user.
  - `/api/currentUser`: Returns user metadata and includes a verifier to satisfy the client check, plus auto-links device ID to the user account on check-in.
  - `/api/ab` & `/api/ab/get`: Address book sync endpoints that merge the user's logged-in devices and tag them with `same-account` to enable passwordless connection.
  - `/api/global-settings`: Public API providing centralized client settings (General & Security) for configuration enforcement.
  - `/login`: Form-based authentication endpoint.
  - `/settings/global`: Post route to configure and update global settings.
  - `/my-devices`: Personal device management endpoint for user account.
  - `/my-devices/save-password`: Connection password manager for unattended access.
  - `/my-devices/claim`: Claims ownership of a device.
  - `/my-devices/unclaim/<device_id>`: Removes device-account association.
* **Internal Logic Overview**:
  - Employs SQLite raw queries with parameterized statements.
  - Implements Vercel Web Interface Guidelines (accessible focus states, non-breaking spacing, tabular-nums for numeric columns, unsaved form warning guards).
