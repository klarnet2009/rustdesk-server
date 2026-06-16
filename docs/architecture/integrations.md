# Integration Documentation

## LDAP / Active Directory Integration

### 1. Purpose
Enables enterprise-wide Single Sign-On (SSO) for remote control administrators using existing organizational directories (Active Directory or openLDAP).

### 2. Authentication Flow
Authentication is performed using the simple bind method:
* Connects to the Active Directory domain controller.
* Authenticates the service account (Bind DN).
* Queries for the target user's distinguished name (DN).
* Tries to bind with the target user's DN and their password to verify credentials.

### 3. API Usage
* **Endpoint**: `/api/ldap/test` (POST)
* **Payload**:
  ```json
  {
    "server": "ldap://dc.company.local",
    "username": "bind_user@company.local",
    "password": "secret_password"
  }
  ```
* **Response**:
  ```json
  {
    "success": true,
    "message": "Connection test successful! Root Base DN discovered.",
    "base_dn": "DC=company,DC=local"
  }
  ```

### 4. Error Handling
* Connection timeouts or network failures are caught and displayed as "Connection test failed: <error>" with `aria-live="polite"` tags.
* Missing system requirements (e.g. `ldap3` package not installed) are flagged inline with remediation recommendations (e.g. `pip install ldap3`).

## Client-Server Passwordless Connection Integration

### 1. Purpose
Enables automatic, secure, passwordless connections between remote desktop client devices (Windows, Android, etc.) that are logged into the same central user account.

### 2. Device Association Flow
* **Login / Status Check**: When a user logs in via `/api/login` or when the client checks current user info via `/api/currentUser`, it sends the client's `id` (device ID) and `uuid`.
* **Automatic Link**: The server automatically registers the device in the `devices` database table and links it to the logged-in user's `user_id`.

### 3. Address Book Sync & Passwordless Tagging
* When the client fetches their address book via `/api/ab` or `/api/ab/get`, the server dynamically queries all devices linked to that user's ID.
* The server merges these owned devices into the returned address book peers list and automatically appends the special tag `"same-account"` to their tags list.
* The client's connection logic (`src/client.rs`) detects the `"same-account"` tag and skips showing the password entry dialog, directly initiating a connection request.

### 4. Connection Handshake Verification
* During the connection handshake, the target host checks if the incoming connection has an `access_token`.
* The host calls `{api_server}/api/currentUser` using the incoming connection's `bearer_auth(access_token)`.
* If the API server returns a valid username that matches the host's own logged-in username, the host authorizes the remote session passwordlessly, bypassing password validation.
