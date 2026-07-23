"""
LDAP/Active Directory Authentication Module
"""

import sqlite3

import os

# Try to import ldap3, if not available, provide stub
try:
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    print("[LDAP] ldap3 not installed. Run: pip install ldap3")

# OpenSSL 3 (the python:3.12-slim base image) dropped MD4 from the default provider,
# but ldap3's NTLM bind computes the NT hash via hashlib.new('MD4', ...), which then
# raises "unsupported hash type MD4" and breaks NTLM auth against AD. Restore MD4 via
# pycryptodome so NTLM works without enabling the OpenSSL legacy provider.
import hashlib
try:
    hashlib.new('md4')
except ValueError:
    try:
        from Crypto.Hash import MD4 as _PyMD4
        _orig_hashlib_new = hashlib.new
        def _hashlib_new_with_md4(name, data=b'', **kwargs):
            if str(name).lower() == 'md4':
                return _PyMD4.new(data or b'')
            return _orig_hashlib_new(name, data, **kwargs)
        hashlib.new = _hashlib_new_with_md4
    except Exception as _md4_err:
        print(f"[LDAP] MD4 shim unavailable ({_md4_err}); NTLM bind may fail")

DB_PATH = os.environ.get('RUSTDESK_DB_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rustdesk.db')


def get_ldap_config():
    """Get LDAP configuration from database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    config = {}
    for row in c.execute("SELECT key, value FROM settings WHERE key LIKE 'ldap_%'").fetchall():
        key = row['key'].replace('ldap_', '')
        config[key] = row['value']
    
    conn.close()
    return config


def is_ldap_enabled():
    """Check if LDAP authentication is enabled"""
    config = get_ldap_config()
    return config.get('enabled') == '1' and LDAP_AVAILABLE


def ldap_authenticate(username, password):
    """
    Authenticate user against LDAP/Active Directory
    
    Returns:
        dict: User info if authenticated, None otherwise
        {
            'username': 'jdoe',
            'email': 'jdoe@example.com',
            'display_name': 'John Doe',
            'groups': ['Domain Users', 'IT Department']
        }
    """
    if not LDAP_AVAILABLE:
        print("[LDAP] ldap3 library not available")
        return None
    
    config = get_ldap_config()
    
    if config.get('enabled') != '1':
        print("[LDAP] LDAP is disabled")
        return None
    
    server_url = config.get('server', '')
    base_dn = config.get('base_dn', '')
    bind_dn = config.get('bind_dn', '')
    bind_password = config.get('bind_password', '')
    
    if not server_url or not base_dn:
        print("[LDAP] Server or Base DN not configured")
        return None
    
    try:
        # Connect to LDAP server
        server = Server(server_url, get_info=ALL)
        
        # Auto-discover Base DN if missing
        if not base_dn:
            base_dn = discover_base_dn(server_url, bind_dn, bind_password) or discover_base_dn(server_url, username, password)
            if not base_dn:
                print(f"[LDAP] Auto-discovery of Base DN failed, cannot proceed")
                return None
            print(f"[LDAP] Auto-discovered Base DN: {base_dn}")
            
        # Try different authentication methods
        user_dn = None
        user_info = None
        
        # Method 1: Direct bind with username@domain (AD style)
        if '@' in username or '\\' in username:
            # Username already contains domain
            user_principal = username
        else:
            # Try to extract domain from server URL or base DN
            domain = extract_domain_from_base_dn(base_dn)
            user_principal = f"{username}@{domain}" if domain else username
        
        # Try NTLM authentication (for Active Directory)
        try:
            conn = Connection(server, user=user_principal, password=password, authentication=NTLM)
            if conn.bind():
                user_info = search_user(conn, base_dn, username)
                conn.unbind()
                if user_info:
                    return user_info
        except Exception as e:
            print(f"[LDAP] NTLM auth failed: {e}")
        
        # Try simple bind with constructed DN
        try:
            # First bind as admin to search for user
            if bind_dn and bind_password:
                admin_conn = Connection(server, user=bind_dn, password=bind_password, authentication=SIMPLE)
                if admin_conn.bind():
                    # Search for user DN
                    user_dn = find_user_dn(admin_conn, base_dn, username)
                    admin_conn.unbind()
            
            if user_dn:
                # Bind as user to verify password
                user_conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE)
                if user_conn.bind():
                    user_info = search_user(user_conn, base_dn, username)
                    user_conn.unbind()
                    if user_info:
                        return user_info
        except Exception as e:
            print(f"[LDAP] Simple bind failed: {e}")
        
        # Try direct bind with sAMAccountName (AD)
        try:
            sam_dn = f"CN={username},{base_dn}"
            conn = Connection(server, user=sam_dn, password=password)
            if conn.bind():
                user_info = {
                    'username': username,
                    'email': f"{username}@{extract_domain_from_base_dn(base_dn)}",
                    'display_name': username,
                    'groups': []
                }
                conn.unbind()
                return user_info
        except Exception as e:
            print(f"[LDAP] Direct CN bind failed: {e}")
        
        print(f"[LDAP] All authentication methods failed for user: {username}")
        return None
        
    except Exception as e:
        print(f"[LDAP] Error: {e}")
        return None


def find_user_dn(conn, base_dn, username):
    """Find user DN by username"""
    search_filter = f"(&(objectClass=person)(|(sAMAccountName={username})(uid={username})(cn={username})))"
    
    conn.search(base_dn, search_filter, attributes=['distinguishedName'])
    
    if conn.entries:
        return str(conn.entries[0].distinguishedName)
    return None


def search_user(conn, base_dn, username):
    """Search for user and return info"""
    search_filter = f"(&(objectClass=person)(|(sAMAccountName={username})(uid={username})(cn={username})))"
    attributes = ['sAMAccountName', 'uid', 'cn', 'mail', 'displayName', 'memberOf', 'givenName', 'sn']
    
    conn.search(base_dn, search_filter, attributes=attributes)
    
    if not conn.entries:
        return None
    
    entry = conn.entries[0]
    
    # Extract username
    user = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else \
           str(entry.uid) if hasattr(entry, 'uid') else \
           str(entry.cn) if hasattr(entry, 'cn') else username
    
    # Extract email
    email = str(entry.mail) if hasattr(entry, 'mail') and entry.mail else f"{user}@localhost"
    
    # Extract display name
    display_name = str(entry.displayName) if hasattr(entry, 'displayName') and entry.displayName else \
                   str(entry.cn) if hasattr(entry, 'cn') else user
    
    # Extract groups
    groups = []
    if hasattr(entry, 'memberOf'):
        for group_dn in entry.memberOf:
            # Extract CN from group DN
            cn_part = str(group_dn).split(',')[0]
            if cn_part.upper().startswith('CN='):
                groups.append(cn_part[3:])
    
    return {
        'username': user,
        'email': email,
        'display_name': display_name,
        'groups': groups
    }


def extract_domain_from_base_dn(base_dn):
    """Extract domain from base DN (e.g., DC=example,DC=com -> example.com)"""
    if not base_dn:
        return None
    
    parts = []
    for part in base_dn.split(','):
        part = part.strip()
        if part.upper().startswith('DC='):
            parts.append(part[3:])
    
    return '.'.join(parts) if parts else None


def sync_ldap_user_to_db(ldap_user, is_admin=False):
    """
    Create or update user in local database from LDAP info
    
    Returns user ID
    """
    import hashlib
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    username = ldap_user['username']
    email = ldap_user.get('email', '')
    display_name = ldap_user.get('display_name', '') or ''

    # Check if user exists
    existing = c.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()

    if existing:
        # Update existing user - ALWAYS update is_admin based on current LDAP groups
        c.execute("UPDATE users SET email = ?, is_admin = ?, display_name = ? WHERE username = ?",
                  (email, 1 if is_admin else 0, display_name, username))
        user_id = existing[0]
        print(f"[LDAP] Updated user '{username}', is_admin={is_admin}")
    else:
        # Create new user with random password (they'll use LDAP auth)
        random_password = hashlib.sha256(f"ldap_{username}_{email}".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, email, is_admin, status, display_name) VALUES (?, ?, ?, ?, 1, ?)",
                  (username, random_password, email, 1 if is_admin else 0, display_name))
        user_id = c.lastrowid
        print(f"[LDAP] Created user '{username}', is_admin={is_admin}")
    
    conn.commit()
    conn.close()

    return user_id


def groups_grant_admin(groups):
    """True if any of the user's AD groups is configured as an admin group."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT value FROM settings WHERE key = 'ldap_admin_groups'").fetchone()
    conn.close()
    if row and row['value'] and row['value'].strip():
        admin_groups = [g.strip() for g in row['value'].split(',') if g.strip()]
    else:
        admin_groups = [
            'Domain Admins', 'Administrators', 'Enterprise Admins',
            'Администраторы домена', 'Администраторы', 'Admins', 'IT Admins', 'RustDesk Admins'
        ]
    return any(g in (groups or []) for g in admin_groups)


def ldap_lookup_user(username):
    """Look up an AD user by name using the service bind (no user password).

    Returns {'username','email','display_name','groups'} or None. Never raises.
    """
    if not LDAP_AVAILABLE:
        return None
    config = get_ldap_config()
    server_url = config.get('server', '')
    base_dn = config.get('base_dn', '')
    bind_dn = config.get('bind_dn', '')
    bind_password = config.get('bind_password', '')
    if not server_url or not base_dn or not bind_dn:
        return None
    try:
        server = Server(server_url, get_info=ALL)
        conn = Connection(server, user=bind_dn, password=bind_password, authentication=NTLM)
        if not conn.bind():
            conn = Connection(server, user=bind_dn, password=bind_password, authentication=SIMPLE)
            if not conn.bind():
                return None
        info = search_user(conn, base_dn, username)
        conn.unbind()
        return info
    except Exception as e:
        print(f"[LDAP] lookup_user failed for {username}: {e}")
        return None


def discover_base_dn(server_url, username=None, password=None):
    """Query Active Directory Root DSE to automatically discover defaultNamingContext (Base DN)"""
    if not LDAP_AVAILABLE or not server_url:
        return None
        
    try:
        server = Server(server_url, get_info=ALL)
        
        # Some ADs allow anonymous RootDSE read, others require authenticated bind. 
        # Attempt authenticated first if credentials provided.
        conn = None
        if username and password:
            # Prefer NTLM for Active Directory simple bindings (username@domain)
            conn = Connection(server, user=username, password=password, authentication=NTLM)
            if not conn.bind():
                # Fallback to simple
                conn = Connection(server, user=username, password=password, authentication=SIMPLE)
                conn.bind()
        else:
            conn = Connection(server)
            conn.bind()
            
        # The defaultNamingContext from server.info
        if server.info and getattr(server.info, 'other', None):
            naming_contexts = server.info.other.get('defaultNamingContext', [])
            if naming_contexts:
                conn.unbind()
                return str(naming_contexts[0])
                
        # Alternative: explicit search on RootDSE
        conn.search('', '(objectClass=*)', search_scope='BASE', attributes=['defaultNamingContext'])
        if conn.entries and hasattr(conn.entries[0], 'defaultNamingContext'):
            base_dn = str(conn.entries[0].defaultNamingContext.value)
            conn.unbind()
            return base_dn
            
    except Exception as e:
        print(f"[LDAP] Auto-discovery failed: {e}")
    
    if conn:
        conn.unbind()
    return None

def test_ldap_connection(test_server=None, test_user=None, test_pass=None):
    """Test LDAP connection with optional provided settings, and attempt Base DN discovery"""
    if not LDAP_AVAILABLE:
        return False, "ldap3 library not installed. Run: pip install ldap3", None
    
    config = get_ldap_config()
    server_url = test_server or config.get('server')
    username = test_user or config.get('bind_dn')
    password = test_pass or config.get('bind_password')
    
    if not server_url:
        return False, "LDAP server not configured", None
    
    try:
        server = Server(server_url, get_info=ALL)
        
        # Attempt Bind
        if username and password:
            conn = Connection(server, user=username, password=password, authentication=NTLM)
            if not conn.bind():
                conn = Connection(server, user=username, password=password, authentication=SIMPLE)
        else:
            conn = Connection(server)
        
        if conn.bind():
            # Discover Base DN
            base_dn = discover_base_dn(server_url, username, password)
            
            info = f"Connected to {server.host}"
            if server.info and server.info.vendor_name:
                 info += f" ({server.info.vendor_name})"
            if base_dn:
                 info += f". Discovered Base DN: {base_dn}"
                 
            conn.unbind()
            return True, info, base_dn
        else:
            return False, f"Bind failed: {conn.result}", None
    
    except Exception as e:
        return False, str(e), None

def sync_all_ldap_users():
    """
    Fetch all users from LDAP/Active Directory and sync them to the database
    """
    if not LDAP_AVAILABLE:
        return False, "LDAP library not available"
        
    config = get_ldap_config()
    if config.get('enabled') != '1':
        return False, "LDAP is disabled"
        
    server_url = config.get('server', '')
    base_dn = config.get('base_dn', '')
    bind_dn = config.get('bind_dn', '')
    bind_password = config.get('bind_password', '')
    
    if not server_url or not base_dn or not bind_dn or not bind_password:
        return False, "LDAP server, base DN, or service account credentials not fully configured"
        
    try:
        server = Server(server_url, get_info=ALL)
        conn = Connection(server, user=bind_dn, password=bind_password, authentication=NTLM)
        if not conn.bind():
            conn = Connection(server, user=bind_dn, password=bind_password, authentication=SIMPLE)
            if not conn.bind():
                return False, "Bind failed with service account credentials"
                
        # Search all persons
        search_filter = "(objectClass=person)"
        attributes = ['sAMAccountName', 'uid', 'cn', 'mail', 'displayName', 'memberOf']
        
        conn.search(base_dn, search_filter, attributes=attributes)
        
        if not conn.entries:
            conn.unbind()
            return True, "No users found in LDAP/AD"
            
        # Get admin groups setting from database
        db_conn = sqlite3.connect(DB_PATH)
        db_conn.row_factory = sqlite3.Row
        c = db_conn.cursor()
        row = c.execute("SELECT value FROM settings WHERE key = 'ldap_admin_groups'").fetchone()
        admin_groups = []
        if row and row['value'].strip():
            admin_groups = [g.strip() for g in row['value'].split(',') if g.strip()]
        else:
            admin_groups = [
                'Domain Admins', 'Administrators', 'Enterprise Admins',
                'Администраторы домена', 'Администраторы', 'Admins', 'IT Admins', 'RustDesk Admins'
            ]
        db_conn.close()
        
        count = 0
        for entry in conn.entries:
            # Extract user info
            user = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') and entry.sAMAccountName else \
                   str(entry.uid) if hasattr(entry, 'uid') and entry.uid else \
                   str(entry.cn) if hasattr(entry, 'cn') and entry.cn else None
                   
            if not user:
                continue
                
            email = str(entry.mail) if hasattr(entry, 'mail') and entry.mail else f"{user}@localhost"
            display_name = str(entry.displayName) if hasattr(entry, 'displayName') and entry.displayName else \
                           str(entry.cn) if hasattr(entry, 'cn') else user
                           
            # Extract groups
            groups = []
            if hasattr(entry, 'memberOf'):
                for group_dn in entry.memberOf:
                    cn_part = str(group_dn).split(',')[0]
                    if cn_part.upper().startswith('CN='):
                        groups.append(cn_part[3:])
                        
            is_admin = any(group in groups for group in admin_groups)
            
            ldap_user = {
                'username': user,
                'email': email,
                'display_name': display_name,
                'groups': groups
            }
            
            sync_ldap_user_to_db(ldap_user, is_admin)
            count += 1
            
        conn.unbind()
        return True, f"Successfully synchronized {count} users from LDAP/Active Directory"
        
    except Exception as e:
        print(f"[LDAP] Sync failed: {e}")
        return False, str(e)

# Test function
if __name__ == '__main__':
    print("LDAP Module Test")
    print(f"LDAP Available: {LDAP_AVAILABLE}")
    
    if LDAP_AVAILABLE:
        success, message = test_ldap_connection()
        print(f"Connection Test: {'OK' if success else 'FAILED'} - {message}")







