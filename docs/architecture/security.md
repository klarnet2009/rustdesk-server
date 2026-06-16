# Security Documentation

## 1. Authentication & Session Security
* **Console Users**: Password hashes are computed using the SHA-256 algorithm with random salt values. Clear-text passwords are never stored in the database.
* **REST APIs**: Secured using JSON Web Tokens (JWT) signed with a securely generated `JWT_SECRET` key. Token expiration is configured to 30 days.
* **Session Cookie**: Encrypted session state storage managed by Flask's `SECRET_KEY`.
* **Role-Based Access Control (RBAC)**: Custom `@admin_required` decorator restricts access to sensitive pages (All Devices, Users, logs, settings) to admin accounts. Non-admins are restricted to the personalized Dashboard and My Devices.
* **Unattended Access Passwords**: Connection passwords for personal devices are saved securely in `rustdesk.db` and passed securely in local protocol calls (over `rustdesk://` custom scheme) without exposing them to other users.

## 2. Multi-Source Authentication Coexistence
To support hybrid deployments, the system enforces a strict hierarchy of authentication providers:
1. **Kerberos (SPNEGO/Negotiate)**: Primarily evaluated for desktop domain users. Validated via secure service ticket exchange.
2. **Active Directory / LDAP (Credentials)**: Checked for domain users when SSO is unavailable, utilizing simple bind authentication.
3. **Local SQLite Credentials**: Evaluated as a local backup and fallback (e.g. for offline local administrators or emergency access).

## 3. LDAP Security
* Active Directory binds are performed securely.
* Password credentials for LDAP simple bind are saved in a settings table in `rustdesk.db`, which is protected from public Web access.

## 4. Web UI Security (Vercel Guidelines compliant)
* **Access Control**: Unsaved changes are monitored on forms to prevent accidental data loss (`beforeunload` listener).
* **Validation**: Inputs are protected by HTML5 validator rules, and server side double-checks type formatting.
* **Autocomplete Rules**: `autocomplete="off"` is set on non-authentication fields to prevent accidental browser cache/autofill leaks.
