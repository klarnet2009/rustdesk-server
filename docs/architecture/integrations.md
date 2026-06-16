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
