# Security Documentation

## 1. Authentication & Session Security
* **Console Users**: Password hashes are computed using the SHA-256 algorithm with random salt values. Clear-text passwords are never stored in the database.
* **REST APIs**: Secured using JSON Web Tokens (JWT) signed with a securely generated `JWT_SECRET` key. Token expiration is configured to 30 days.
* **Session Cookie**: Encrypted session state storage managed by Flask's `SECRET_KEY`.

## 2. LDAP Security
* Active Directory binds are performed securely.
* Password credentials for LDAP simple bind are saved in a settings table in `rustdesk.db`, which is protected from public Web access.

## 3. Web UI Security (Vercel Guidelines compliant)
* **Access Control**: Unsaved changes are monitored on forms to prevent accidental data loss (`beforeunload` listener).
* **Validation**: Inputs are protected by HTML5 validator rules, and server side double-checks type formatting.
* **Autocomplete Rules**: `autocomplete="off"` is set on non-authentication fields to prevent accidental browser cache/autofill leaks.
