#!/usr/bin/env python3
"""
RustDesk Web Management Panel
Tailwind CSS + DataTables + Chart.js

Запуск: python server.py
URL: http://localhost:21114
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, make_response, send_from_directory
from functools import wraps
import jwt
import json
import time
import hashlib
import hmac
import re
import secrets
import os
import sqlite3
import urllib.request
from datetime import datetime, timedelta
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

# LDAP Module
try:
    import ldap_auth
    from ldap_auth import (
        ldap_authenticate,
        is_ldap_enabled,
        sync_ldap_user_to_db,
        test_ldap_connection,
        LDAP_AVAILABLE
    )
except ImportError:
    LDAP_AVAILABLE = False
    def ldap_authenticate(u, p): return None
    def is_ldap_enabled(): return False
    def sync_ldap_user_to_db(u, a=False): return None
    def test_ldap_connection(): return False, "LDAP module not found"

import sso_kerberos
SSO_SPN = os.environ.get('SSO_SPN', '')

DB_PATH = os.environ.get('RUSTDESK_DB_PATH') or os.path.join(os.path.dirname(__file__), 'rustdesk.db')

def _load_or_create_secret(env_var, settings_key):
    """Resolve a persistent secret: env var > settings table > generate once.

    Never falls back to a hardcoded value: a secret shipped in source code
    lets anyone forge sessions/JWTs (release-blocker).
    """
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (settings_key,)).fetchone()
        if row and row['value']:
            conn.close()
            return row['value']
        generated = secrets.token_hex(32)
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (settings_key, generated))
        conn.commit()
        conn.close()
        print(f"[SECURITY] Generated new {settings_key} and stored it in the settings table")
        return generated
    except sqlite3.OperationalError:
        # settings table not created yet (first import before init_db) —
        # fall back to a process-local random secret; it will be persisted
        # on next call once the table exists.
        return secrets.token_hex(32)

app = Flask(__name__)
app.secret_key = _load_or_create_secret('SECRET_KEY', 'flask_secret_key')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', 'false').lower() == 'true',
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Enable CORS for API endpoints
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

# Configuration
HOST = os.environ.get('API_HOST', '0.0.0.0')  # Listen on all interfaces
PORT = int(os.environ.get('API_PORT', 21114))

_JWT_SECRET_CACHE = None

def get_jwt_secret():
    """JWT signing secret, persisted per-installation (env JWT_SECRET overrides)."""
    global _JWT_SECRET_CACHE
    if _JWT_SECRET_CACHE is None:
        _JWT_SECRET_CACHE = _load_or_create_secret('JWT_SECRET', 'jwt_secret')
    return _JWT_SECRET_CACHE

# SSL Configuration
SSL_ENABLED = os.environ.get('SSL_ENABLED', 'false').lower() == 'true'
SSL_CERT = os.path.join(os.path.dirname(__file__), '10.21.31.11+2.pem')
SSL_KEY = os.path.join(os.path.dirname(__file__), '10.21.31.11+2-key.pem')

# Static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')

# ==================== DATABASE ====================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        is_admin INTEGER DEFAULT 0,
        status INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        uuid TEXT,
        hostname TEXT,
        os TEXT,
        username TEXT,
        version TEXT,
        cpu TEXT,
        memory TEXT,
        ip TEXT,
        group_name TEXT DEFAULT 'Default',
        user_id INTEGER,
        online INTEGER DEFAULT 0,
        last_seen TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS address_books (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        data TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY,
        type TEXT,
        device_id TEXT,
        peer_id TEXT,
        action TEXT,
        data TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY,
        device_id TEXT,
        peer_id TEXT,
        conn_type TEXT,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ended_at TIMESTAMP,
        duration INTEGER
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    
    # Default admin
    try:
        c.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                  ('admin', hash_password('admin123'), 'admin@localhost', 1))
    except sqlite3.IntegrityError:
        pass
    
    # Check if 'password' column exists in devices
    try:
        c.execute("SELECT password FROM devices LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE devices ADD COLUMN password TEXT")
        print("[DB] Added password column to devices table")

    # Check if 'display_name' column exists in users (AD display name)
    try:
        c.execute("SELECT display_name FROM users LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT ''")
        print("[DB] Added display_name column to users table")

    # auth_source: 'local' = panel-managed password, 'ldap' = domain-managed (JIT).
    # Domain rows never authenticate with a local password; local rows are never
    # taken over by same-named domain accounts.
    try:
        c.execute("SELECT auth_source FROM users LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'local'")
        print("[DB] Added auth_source column to users table")

    # One-time cleanup of the retired bulk LDAP sync artifacts:
    # - its (objectClass=person) filter also imported AD computer/trust accounts
    #   (sAMAccountName ends with '$') — drop them;
    # - it stored the PREDICTABLE legacy-sha256 password sha256('ldap_<user>_<email>')
    #   which verify_password() accepted as a login. Purge unreferenced rows (they
    #   are re-created by JIT on next login); neutralize referenced ones.
    deleted = c.execute("DELETE FROM users WHERE username LIKE '%$'").rowcount
    for row in c.execute("SELECT id, username, email FROM users WHERE length(password) = 64").fetchall():
        marker = hashlib.sha256(f"ldap_{row[1]}_{row[2]}".encode()).hexdigest()
        if c.execute("SELECT 1 FROM users WHERE id = ? AND password = ?", (row[0], marker)).fetchone():
            referenced = c.execute(
                "SELECT 1 FROM devices WHERE user_id = ? UNION SELECT 1 FROM address_books WHERE user_id = ? LIMIT 1",
                (row[0], row[0])).fetchone()
            if referenced:
                c.execute("UPDATE users SET password = ?, auth_source = 'ldap' WHERE id = ?",
                          ('ldap$' + secrets.token_hex(16), row[0]))
            else:
                c.execute("DELETE FROM users WHERE id = ?", (row[0],))
                deleted += 1
    if deleted:
        print(f"[DB] Purged {deleted} bulk-LDAP-sync artifact rows from users")

    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

PBKDF2_ITERATIONS = 200_000

def hash_password(password, salt=None):
    """pbkdf2-sha256 with per-password salt: 'pbkdf2$<salt_hex>$<hash_hex>'."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f'pbkdf2${salt}${dk.hex()}'

def verify_password(password, stored):
    """Verify against pbkdf2 hash; transparently accepts legacy unsalted sha256."""
    if not stored:
        return False
    if stored.startswith('pbkdf2$'):
        try:
            _, salt, _ = stored.split('$')
        except ValueError:
            return False
        return hmac.compare_digest(hash_password(password, salt), stored)
    # Legacy: unsalted sha256 hex
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)

def maybe_upgrade_password(conn, user, password):
    """Re-hash legacy sha256-stored passwords to pbkdf2 on successful login."""
    stored = user['password'] or ''
    if stored and not stored.startswith('pbkdf2$'):
        conn.execute("UPDATE users SET password = ? WHERE id = ?",
                     (hash_password(password), user['id']))
        conn.commit()
        print(f"[SECURITY] Migrated password hash to pbkdf2 for user '{user['username']}'")

def sanitize_field(value, max_len=128):
    """Strip control chars and HTML/JS-breaking characters from client-supplied fields.

    Fields like hostname arrive via unauthenticated /api/sysinfo and are later
    rendered in the web panel — this is a stored-XSS vector without filtering.
    """
    if not isinstance(value, str):
        return ''
    cleaned = ''.join(ch for ch in value if ch.isprintable() and ch not in '<>"\'\\`&;')
    return cleaned[:max_len].strip()

def audit_device_event(conn, device_id, action, data):
    conn.execute("INSERT INTO audit_logs (type, device_id, peer_id, action, data) VALUES (?, ?, ?, ?, ?)",
                 ('device', device_id, '', action, json.dumps(data, ensure_ascii=False)))

def assign_device_to_user(conn, device_id, uuid, user_id, username):
    """Link device to user, auditing ownership changes (incl. reassignment)."""
    existing = conn.execute("SELECT user_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    conn.execute("INSERT OR IGNORE INTO devices (id, uuid, online) VALUES (?, ?, 0)", (device_id, uuid))
    conn.execute("UPDATE devices SET user_id = ?, uuid = COALESCE(NULLIF(?, ''), uuid) WHERE id = ?",
                 (user_id, uuid, device_id))
    if existing and existing['user_id'] and existing['user_id'] != user_id:
        audit_device_event(conn, device_id, 'reassigned', {
            'from_user_id': existing['user_id'], 'to_user_id': user_id, 'to_username': username})
        print(f"[MY DEVICES] Device {device_id} reassigned from user {existing['user_id']} to {username}")
    conn.commit()

def get_ldap_admin_groups(conn):
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = 'ldap_admin_groups'").fetchone()
        if row and row['value'].strip():
            return [g.strip() for g in row['value'].split(',') if g.strip()]
    except Exception:
        pass
    return [
        'Domain Admins',
        'Administrators',
        'Enterprise Admins',
        'Администраторы домена',
        'Администраторы',
        'Admins',
        'IT Admins',
        'RustDesk Admins',
    ]

# ==================== AUTH ====================

def create_token(user_id, username, is_admin):
    return jwt.encode({
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        'exp': time.time() + 86400 * 30
    }, get_jwt_secret(), algorithm="HS256")

def resolve_sso_user(principal):
    """Map a verified Kerberos principal to a panel user.

    LDAP enabled + found -> enrich (email, display_name, admin-by-group) + JIT.
    Otherwise -> minimal JIT (non-admin, empty password, synthesized email).
    Returns {'user_id', 'username', 'is_admin', 'email'}.
    """
    username = sanitize_field(principal.split('@')[0].strip().lower(), 64)
    realm = principal.split('@', 1)[1].lower() if '@' in principal else 'domain.local'

    if ldap_auth.is_ldap_enabled():
        info = ldap_auth.ldap_lookup_user(username)
        if info:
            is_admin = ldap_auth.groups_grant_admin(info.get('groups'))
            user_id = ldap_auth.sync_ldap_user_to_db(info, is_admin)
            if user_id is None:
                # Collides with a panel-managed local account — never let a
                # domain principal impersonate it.
                print(f"[SSO] '{username}' collides with a local account, refusing SSO mapping")
                return None
            return {'user_id': user_id, 'username': info['username'],
                    'is_admin': is_admin, 'email': info.get('email', '')}

    # Minimal JIT (domain-managed row; empty password is unusable for login)
    email = f"{username}@{realm}"
    conn = get_db()
    row = conn.execute("SELECT id, auth_source FROM users WHERE username = ?", (username,)).fetchone()
    if row:
        if (row['auth_source'] or 'local') == 'local':
            conn.close()
            print(f"[SSO] '{username}' collides with a local account, refusing SSO mapping")
            return None
        user_id = row['id']
    else:
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password, email, is_admin, status, auth_source) VALUES (?, '', ?, 0, 1, 'ldap')",
                    (username, email))
        user_id = cur.lastrowid
        conn.commit()
    conn.close()
    return {'user_id': user_id, 'username': username, 'is_admin': False, 'email': email}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "Token required"}), 401
        try:
            data = jwt.decode(token, get_jwt_secret(), algorithms=["HS256"])
            request.current_user = data
        except:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def web_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('web_login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('web_login'))
        if not session.get('is_admin'):
            return redirect(url_for('web_my_devices'))
        return f(*args, **kwargs)
    return decorated

# ==================== STATIC FILES ====================

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(STATIC_DIR, filename)

# ==================== TEMPLATES ====================

BASE_HTML = r'''
<!DOCTYPE html>
<html lang="en" data-theme="corporate">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - RustDesk Panel</title>
    <script>
      // Set data-theme before the stylesheet paints so switching themes
      // doesn't flash the other theme on every navigation (was previously
      // only applied from a <script> at the end of <body>).
      document.documentElement.setAttribute('data-theme', localStorage.getItem('theme') || 'corporate');
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link href="/static/output.css" rel="stylesheet">
    <style>
      body{font-family:'IBM Plex Sans',system-ui,-apple-system,sans-serif}
      .card-title{font-size:1.125rem;line-height:1.4;font-weight:600}
    </style>
    <script src="https://unpkg.com/lucide@1.26.0"></script>
</head>
<body class="min-h-screen bg-base-200">
    <a href="#main" class="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:top-2 focus:left-2 btn btn-primary btn-sm">Skip to content</a>
    <!-- Global toast stack. aria-live=polite so screen readers announce
         transient messages; individual toasts auto-dismiss (see showToast). -->
    <div id="toastStack" class="toast toast-top toast-end z-[100]" aria-live="polite" aria-atomic="false"></div>
    <div class="drawer lg:drawer-open">
        <input id="sidebar-drawer" type="checkbox" class="drawer-toggle" />
        
        <div class="drawer-content flex flex-col min-h-screen">
            <!-- Top Navbar -->
            <header class="navbar bg-base-100 border-b border-base-300 px-6 justify-between shadow-sm z-10">
                <div class="flex-none lg:hidden">
                    <label for="sidebar-drawer" class="btn btn-square btn-ghost" aria-label="Toggle Sidebar">
                        <i data-lucide="menu" class="w-6 h-6" aria-hidden="true"></i>
                    </label>
                </div>
                <div class="flex-grow">
                    <span id="liveClock" class="text-sm text-base-content/70 tabular-nums font-mono" title="Your local time">{{ current_time }}</span>
                </div>
                <div class="flex-none gap-2">
                    <!-- Theme Toggle -->
                    <button class="btn btn-ghost btn-circle" onclick="toggleTheme()" title="Toggle Theme" aria-label="Toggle Theme" id="themeIconContainer">
                        <i data-lucide="moon" class="w-5 h-5" aria-hidden="true"></i>
                    </button>
                    
                    <!-- User Dropdown -->
                    <div class="dropdown dropdown-end">
                        <button type="button" tabindex="0" aria-haspopup="menu" class="btn btn-ghost m-1 flex items-center gap-2 normal-case font-medium">
                            <i data-lucide="user" class="w-5 h-5 opacity-70" aria-hidden="true"></i>
                            {{ session.username }}
                            <i data-lucide="chevron-down" class="w-4 h-4 opacity-50" aria-hidden="true"></i>
                        </button>
                        <ul tabindex="0" class="dropdown-content z-[30] menu p-2 shadow bg-base-100 rounded-box w-52 border border-base-300 mt-2">
                            <li>
                                <a href="{{ url_for('web_logout') }}" class="text-error">
                                    <i data-lucide="log-out" class="w-4 h-4" aria-hidden="true"></i> Logout
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </header>

            <!-- Content Area -->
            <main id="main" class="p-6 flex-grow bg-base-200 motion-safe:rise-in">
                {% block content %}{% endblock %}
            </main>
        </div>

        <!-- Sidebar -->
        <div class="drawer-side z-20">
            <label for="sidebar-drawer" aria-label="close sidebar" class="drawer-overlay"></label>
            <div class="p-4 w-64 min-h-full bg-base-100 border-r border-base-300 text-base-content flex flex-col">
                <!-- Brand -->
                <div class="px-4 py-3 border-b border-base-300 mb-4">
                    <a href="/" class="flex items-center gap-2 text-xl font-bold text-base-content no-underline">
                        <i data-lucide="monitor" class="text-primary w-6 h-6" aria-hidden="true"></i>
                        <span>RustDesk Panel</span>
                    </a>
                </div>
                <!-- Nav Links -->
                <nav aria-label="Primary" class="flex-grow">
                <ul class="menu menu-vertical p-0 gap-1">
                    <li>
                        <a class="{{ 'active bg-primary text-primary-content font-semibold' if active_page == 'dashboard' else '' }}" href="{{ url_for('web_dashboard') }}" aria-current="{{ 'page' if active_page == 'dashboard' else 'false' }}">
                            <i data-lucide="layout-dashboard" class="w-5 h-5" aria-hidden="true"></i>
                            Dashboard
                        </a>
                    </li>
                    <li>
                        <a class="{{ 'active bg-primary text-primary-content font-semibold' if active_page == 'my_devices' else '' }}" href="{{ url_for('web_my_devices') }}" aria-current="{{ 'page' if active_page == 'my_devices' else 'false' }}">
                            <i data-lucide="monitor" class="w-5 h-5" aria-hidden="true"></i>
                            My Devices
                        </a>
                    </li>
                    {% if session.is_admin %}
                    <li>
                        <a class="{{ 'active bg-primary text-primary-content font-semibold' if active_page == 'devices' else '' }}" href="{{ url_for('web_devices') }}" aria-current="{{ 'page' if active_page == 'devices' else 'false' }}">
                            <i data-lucide="shield" class="w-5 h-5" aria-hidden="true"></i>
                            All Devices
                        </a>
                    </li>
                    <li>
                        <a class="{{ 'active bg-primary text-primary-content font-semibold' if active_page == 'users' else '' }}" href="{{ url_for('web_users') }}" aria-current="{{ 'page' if active_page == 'users' else 'false' }}">
                            <i data-lucide="users" class="w-5 h-5" aria-hidden="true"></i>
                            Users
                        </a>
                    </li>
                    <li>
                        <a class="{{ 'active bg-primary text-primary-content font-semibold' if active_page == 'logs' else '' }}" href="{{ url_for('web_logs') }}" aria-current="{{ 'page' if active_page == 'logs' else 'false' }}">
                            <i data-lucide="clipboard-list" class="w-5 h-5" aria-hidden="true"></i>
                            Logs
                        </a>
                    </li>
                    <li>
                        <a class="{{ 'active bg-primary text-primary-content font-semibold' if active_page == 'settings' else '' }}" href="{{ url_for('web_settings') }}" aria-current="{{ 'page' if active_page == 'settings' else 'false' }}">
                            <i data-lucide="settings" class="w-5 h-5" aria-hidden="true"></i>
                            Settings
                        </a>
                    </li>
                    {% endif %}
                </ul>
                </nav>
                <!-- Footer -->
                <div class="mt-auto pt-4 border-t border-base-300">
                    <small class="text-base-content/60">RustDesk Panel v2.0</small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js"></script>
    <script>
        // Shared DataTables -> DaisyUI styling helper (P3).
        // Wraps DataTables init so the injected filter box, length menu, info
        // line and pagination get DaisyUI classes instead of browser defaults
        // (which fail contrast in the dark "business" theme). Callers pass the
        // same options they'd give .DataTable(); pageLength / language / order
        // are preserved. Re-applies on every draw (pagination is regenerated).
        window.initDataTable = function(selector, opts) {
            opts = opts || {};
            function styleControls(settings) {
                const wrap = $(settings.nTableWrapper);
                wrap.find('.dataTables_filter input').addClass('input input-bordered input-sm');
                wrap.find('.dataTables_length select').addClass('select select-bordered select-sm');
                wrap.find('.dataTables_info').addClass('text-sm text-base-content/70');
                wrap.find('.dataTables_paginate .paginate_button').addClass('btn btn-sm btn-ghost');
                wrap.find('.dataTables_paginate .paginate_button.current').addClass('btn-active');
                if (window.lucide) { lucide.createIcons(); }
            }
            const userInitComplete = opts.initComplete;
            const userDrawCallback = opts.drawCallback;
            opts.initComplete = function(settings, json) {
                styleControls(settings);
                if (typeof userInitComplete === 'function') { userInitComplete.call(this, settings, json); }
            };
            opts.drawCallback = function(settings) {
                styleControls(settings);
                if (typeof userDrawCallback === 'function') { userDrawCallback.call(this, settings); }
            };
            return $(selector).DataTable(opts);
        };

        // Chart.js instances register here so the theme toggle can re-color
        // them in place (P6) instead of doing a full-page location.reload().
        window.__charts = window.__charts || [];

        // Resolve the DaisyUI semantic tokens the charts use into concrete
        // oklch() color strings for the *current* theme. DaisyUI stores each
        // token as raw oklch components (e.g. --p: 69.79% 0.19 44.9), so we
        // wrap them in oklch(); alpha via the " / a" syntax. Re-reading these
        // after data-theme changes yields the new theme's palette.
        window.getChartThemeColors = function() {
            const cs = getComputedStyle(document.documentElement);
            const tok = function(name, alpha) {
                const raw = cs.getPropertyValue(name).trim();
                if (!raw) { return null; }
                return alpha != null ? 'oklch(' + raw + ' / ' + alpha + ')' : 'oklch(' + raw + ')';
            };
            return {
                primary: tok('--p'),
                primaryFill: tok('--p', 0.12),
                text: tok('--bc', 0.7),   // muted-text token: base-content/70
                grid: tok('--b3'),        // grid lines match the base-300 borders
                // Categorical palette for pie/doughnut segments (semantic
                // tokens so they re-theme automatically): primary, info,
                // success, warning, error.
                palette: [tok('--p'), tok('--in'), tok('--su'), tok('--wa'), tok('--er')]
            };
        };

        // Theme toggle
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'business' ? 'corporate' : 'business';

            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon();

            // Re-theme charts IN PLACE — recolor each registered Chart.js
            // instance from the new theme's tokens (no reload / flash / scroll
            // loss). update('none') snaps colors without a transition tween.
            if (window.__charts && window.__charts.length) {
                const colors = window.getChartThemeColors();
                window.__charts.forEach(function(ch) {
                    if (ch && typeof ch.__recolor === 'function') {
                        ch.__recolor(colors);
                        ch.update('none');
                    }
                });
            }
        }

        function updateThemeIcon() {
            const iconContainer = document.getElementById('themeIconContainer');
            if (iconContainer) {
                const isDark = document.documentElement.getAttribute('data-theme') === 'business';
                iconContainer.innerHTML = isDark 
                    ? '<i data-lucide="sun" class="w-5 h-5" aria-hidden="true"></i>' 
                    : '<i data-lucide="moon" class="w-5 h-5" aria-hidden="true"></i>';
                if (window.lucide) {
                    lucide.createIcons();
                }
            }
        }

        // Transient toast notification (auto-dismisses in 3.5s). type ∈
        // success|error|warning|info. Replaces scattered window.alert() calls
        // with a themed, non-blocking, theme-aware surface.
        window.showToast = function(message, type) {
            type = type || 'info';
            const stack = document.getElementById('toastStack');
            if (!stack) { return; }
            const icons = { success: 'check-circle-2', error: 'alert-circle', warning: 'triangle-alert', info: 'info' };
            const el = document.createElement('div');
            el.className = 'toast-item alert alert-' + type + ' shadow-lg max-w-sm';
            el.setAttribute('role', type === 'error' ? 'alert' : 'status');
            el.innerHTML = '<i data-lucide="' + (icons[type] || 'info') + '" class="w-5 h-5 shrink-0" aria-hidden="true"></i><span class="text-sm">' + String(message).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])) + '</span>';
            stack.appendChild(el);
            if (window.lucide) { lucide.createIcons(); }
            setTimeout(() => {
                el.style.transition = 'opacity 0.3s';
                el.style.opacity = '0';
                setTimeout(() => el.remove(), 300);
            }, 3500);
        };

        // Header clock — client-rendered so it actually ticks (the old
        // server-rendered timestamp never updated after page load).
        function tickClock() {
            const el = document.getElementById('liveClock');
            if (el) {
                el.textContent = new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
            }
        }

        // Themed replacement for window.confirm() — native confirm() ignores
        // the corporate/business theme and looks inconsistent with the
        // app's own <dialog> modals. Usage: confirmDialog('Delete X?', () =>
        // doTheThing()). Builds one reusable <dialog> lazily on first call.
        window.confirmDialog = function(message, onConfirm, opts) {
            opts = opts || {};
            let dlg = document.getElementById('sharedConfirmDialog');
            if (!dlg) {
                dlg = document.createElement('dialog');
                dlg.id = 'sharedConfirmDialog';
                dlg.className = 'modal';
                dlg.innerHTML = `
                    <div class="modal-box max-w-sm">
                        <div class="flex items-start gap-3">
                            <div class="w-10 h-10 rounded-full bg-error/10 text-error flex items-center justify-center shrink-0">
                                <i data-lucide="triangle-alert" class="w-5 h-5" aria-hidden="true"></i>
                            </div>
                            <p id="sharedConfirmMessage" class="text-sm pt-2"></p>
                        </div>
                        <div class="flex justify-end gap-3 mt-6">
                            <button type="button" class="btn btn-ghost btn-sm" id="sharedConfirmCancel">Cancel</button>
                            <button type="button" class="btn btn-error btn-sm" id="sharedConfirmOk">Confirm</button>
                        </div>
                    </div>
                    <form method="dialog" class="modal-backdrop"><button>close</button></form>
                `;
                document.body.appendChild(dlg);
            }
            dlg.querySelector('#sharedConfirmMessage').textContent = message;
            const okBtn = dlg.querySelector('#sharedConfirmOk');
            okBtn.textContent = opts.confirmLabel || 'Confirm';
            const cancelBtn = dlg.querySelector('#sharedConfirmCancel');
            const cleanup = () => { okBtn.replaceWith(okBtn.cloneNode(true)); };
            dlg.showModal();
            if (window.lucide) { lucide.createIcons(); }
            dlg.querySelector('#sharedConfirmOk').addEventListener('click', function() {
                dlg.close();
                cleanup();
                onConfirm();
            }, { once: true });
            cancelBtn.onclick = () => dlg.close();
        };

        document.addEventListener('DOMContentLoaded', () => {
            updateThemeIcon();
            tickClock();
            setInterval(tickClock, 1000);
            if (window.lucide) {
                lucide.createIcons();
            }

            // Flash toast that survives a page reload (set before location.reload()).
            try {
                const flash = sessionStorage.getItem('flashToast');
                if (flash) {
                    sessionStorage.removeItem('flashToast');
                    const { m, t } = JSON.parse(flash);
                    window.showToast(m, t || 'info');
                }
            } catch (e) { /* ignore */ }

            // Handle form submission loading states
            document.addEventListener('submit', (e) => {
                const form = e.target;
                const btn = form.querySelector('button[type="submit"]');
                if (btn && form.checkValidity()) {
                    const label = btn.dataset.loadingText || 'Working…';
                    btn.classList.add('btn-disabled');
                    btn.disabled = true;
                    btn.innerHTML = `<span class="loading loading-spinner loading-sm" aria-hidden="true"></span> ${label}`;
                }
            });
        });
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>
'''

LOGIN_HTML = r'''
<!DOCTYPE html>
<html lang="en" data-theme="corporate">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - RustDesk Panel</title>
    <script>
      document.documentElement.setAttribute('data-theme', localStorage.getItem('theme') || 'corporate');
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link href="/static/output.css" rel="stylesheet">
    <style>
      body{font-family:'IBM Plex Sans',system-ui,-apple-system,sans-serif}
      .card-title{font-size:1.125rem;line-height:1.4;font-weight:600}
      .login-backdrop{
        background:
          radial-gradient(ellipse 80% 60% at 50% -10%, oklch(var(--p) / 0.16), transparent),
          radial-gradient(ellipse 60% 50% at 100% 100%, oklch(var(--in) / 0.08), transparent);
      }
    </style>
    <script src="https://unpkg.com/lucide@1.26.0"></script>
</head>
<body class="min-h-screen bg-base-200 login-backdrop flex items-center justify-center p-4">
    <div class="card w-full max-w-sm bg-base-100 shadow-xl border border-base-300">
        <div class="card-body p-8">
            <div class="flex flex-col items-center mb-6">
                <div class="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mb-4">
                    <i data-lucide="monitor" class="w-8 h-8 text-primary" aria-hidden="true"></i>
                </div>
                <h1 class="card-title text-2xl font-bold text-base-content text-balance">RustDesk Panel</h1>
                <p class="text-sm text-base-content/60">Sign in to your account</p>
            </div>

            {% if error %}
            <div class="alert alert-error shadow-sm mb-4" aria-live="polite">
                <i data-lucide="alert-circle" class="w-5 h-5" aria-hidden="true"></i>
                <span class="text-sm font-semibold">{{ error }}</span>
            </div>
            {% endif %}

            <form method="POST" class="space-y-4">
                <div class="form-control w-full">
                    <label class="label" for="login-username"><span class="label-text font-semibold">Username</span></label>
                    <label class="input input-bordered flex items-center gap-2">
                        <i data-lucide="user" class="w-4 h-4 opacity-50" aria-hidden="true"></i>
                        <input type="text" id="login-username" class="grow" name="username" placeholder="Username… e.g. admin" required autocomplete="username" spellcheck="false" autofocus />
                    </label>
                </div>

                <div class="form-control w-full">
                    <label class="label" for="login-password"><span class="label-text font-semibold">Password</span></label>
                    <label class="input input-bordered flex items-center gap-2">
                        <i data-lucide="lock" class="w-4 h-4 opacity-50" aria-hidden="true"></i>
                        <input type="password" id="login-password" class="grow" name="password" placeholder="Password…" required autocomplete="current-password" spellcheck="false" />
                        <button type="button" class="btn btn-ghost btn-xs btn-square" id="toggleLoginPassword" aria-label="Show password">
                            <i data-lucide="eye" id="toggleLoginPasswordIcon" class="w-4 h-4 opacity-50" aria-hidden="true"></i>
                        </button>
                    </label>
                    <span id="capsLockHint" class="hidden label-text-alt text-warning mt-1 flex items-center gap-1" aria-live="polite">
                        <i data-lucide="triangle-alert" class="w-3.5 h-3.5" aria-hidden="true"></i>Caps Lock is on
                    </span>
                </div>

                <div class="card-actions justify-end mt-6">
                    <button type="submit" class="btn btn-primary w-full">
                        <i data-lucide="log-in" class="w-4 h-4" aria-hidden="true"></i> Sign In
                    </button>
                </div>
            </form>
        </div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            if (window.lucide) {
                lucide.createIcons();
            }

            // Handle login form submission loading states
            const form = document.querySelector('form');
            if (form) {
                form.addEventListener('submit', (e) => {
                    const btn = form.querySelector('button[type="submit"]');
                    if (btn && form.checkValidity()) {
                        btn.classList.add('btn-disabled');
                        btn.innerHTML = `<span class="loading loading-spinner loading-sm" aria-hidden="true"></span> Signing In…`;
                    }
                });
            }

            const toggleBtn = document.getElementById('toggleLoginPassword');
            const pwInput = document.getElementById('login-password');
            if (toggleBtn && pwInput) {
                toggleBtn.addEventListener('click', () => {
                    const showing = pwInput.type === 'text';
                    pwInput.type = showing ? 'password' : 'text';
                    toggleBtn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
                    document.getElementById('toggleLoginPasswordIcon').setAttribute('data-lucide', showing ? 'eye' : 'eye-off');
                    if (window.lucide) { lucide.createIcons(); }
                });
            }

            // Caps Lock warning on the password field — a classic silent
            // cause of "wrong password" frustration.
            const capsHint = document.getElementById('capsLockHint');
            if (pwInput && capsHint) {
                const checkCaps = (e) => {
                    if (e.getModifierState) {
                        capsHint.classList.toggle('hidden', !e.getModifierState('CapsLock'));
                    }
                };
                pwInput.addEventListener('keydown', checkCaps);
                pwInput.addEventListener('keyup', checkCaps);
                pwInput.addEventListener('blur', () => capsHint.classList.add('hidden'));
            }
        });
    </script>
</body>
</html>
'''

DASHBOARD_HTML = r'''
{% extends "base" %}
{% block content %}
<div class="flex flex-wrap items-center justify-between gap-3 mb-6">
    <h1 class="text-2xl font-bold text-base-content text-balance">Dashboard</h1>
    <div class="flex items-center gap-2 text-sm text-base-content/70" aria-live="polite">
        <span id="liveDot" class="live-dot is-live" aria-hidden="true"></span>
        <span id="liveStatus">Live</span>
        <span class="text-base-content/40">·</span>
        <span>updated <span id="lastUpdated" class="tabular-nums font-mono">just now</span></span>
    </div>
</div>

<!-- Stats -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="stats shadow-sm bg-base-100 border border-base-300 p-2">
        <div class="stat flex items-center gap-4">
            <div class="stat-figure text-primary">
                <div class="w-12 h-12 bg-primary/10 text-primary rounded-lg flex items-center justify-center">
                    <i data-lucide="monitor" class="w-6 h-6" aria-hidden="true"></i>
                </div>
            </div>
            <div>
                <div class="stat-value text-3xl font-bold text-base-content mb-1 tabular-nums" data-kpi="total" aria-live="polite">{{ stats.total }}</div>
                <div class="stat-title text-sm text-base-content/70">Total Devices</div>
            </div>
        </div>
    </div>

    <div class="stats shadow-sm bg-base-100 border border-base-300 border-l-4 border-l-success p-2">
        <div class="stat flex items-center gap-4">
            <div class="stat-figure text-success">
                <div class="w-12 h-12 bg-success/10 text-success rounded-lg flex items-center justify-center">
                    <i data-lucide="wifi" class="w-6 h-6" aria-hidden="true"></i>
                </div>
            </div>
            <div>
                <div class="stat-value text-3xl font-bold text-success mb-1 tabular-nums" data-kpi="online" aria-live="polite">{{ stats.online }}</div>
                <div class="stat-title text-sm text-base-content/70">Online Now</div>
            </div>
        </div>
    </div>
    
    <div class="stats shadow-sm bg-base-100 border border-base-300 p-2">
        <div class="stat flex items-center gap-4">
            <div class="stat-figure text-secondary">
                <div class="w-12 h-12 bg-secondary/10 text-secondary rounded-lg flex items-center justify-center">
                    <i data-lucide="arrow-left-right" class="w-6 h-6" aria-hidden="true"></i>
                </div>
            </div>
            <div>
                <div class="stat-value text-3xl font-bold text-base-content mb-1 tabular-nums" data-kpi="connections_today" aria-live="polite">{{ stats.connections_today }}</div>
                <div class="stat-title text-sm text-base-content/70">Connections Today</div>
            </div>
        </div>
    </div>
    
    <div class="stats shadow-sm bg-base-100 border border-base-300 p-2">
        <div class="stat flex items-center gap-4">
            <div class="stat-figure text-warning">
                <div class="w-12 h-12 bg-warning/10 text-warning rounded-lg flex items-center justify-center">
                    <i data-lucide="users" class="w-6 h-6" aria-hidden="true"></i>
                </div>
            </div>
            <div>
                <div class="stat-value text-3xl font-bold text-base-content mb-1 tabular-nums" data-kpi="users" aria-live="polite">{{ stats.users }}</div>
                <div class="stat-title text-sm text-base-content/70">Users</div>
            </div>
        </div>
    </div>
</div>

<!-- Charts -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
    <div class="lg:col-span-2 card bg-base-100 border border-base-300 shadow-sm">
        <div class="card-body p-5">
            <h2 class="card-title text-base font-semibold text-balance">Connections (Last 7&nbsp;Days)</h2>
            {% if chart_data and chart_data|sum > 0 %}
            <div class="relative h-72">
                <canvas id="connectionsChart" role="img" aria-label="Connections per day over the last 7 days: {% for i in range(chart_labels|length) %}{{ chart_labels[i] }}: {{ chart_data[i] }}{{ ', ' if not loop.last }}{% endfor %}"></canvas>
            </div>
            <table class="sr-only">
                <caption>Connections per day, last 7 days</caption>
                <thead><tr><th scope="col">Date</th><th scope="col">Connections</th></tr></thead>
                <tbody>
                    {% for i in range(chart_labels|length) %}
                    <tr><td>{{ chart_labels[i] }}</td><td>{{ chart_data[i] }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="h-72 flex flex-col items-center justify-center text-center">
                <i data-lucide="line-chart" class="w-10 h-10 opacity-30 mb-2" aria-hidden="true"></i>
                <p class="text-sm text-base-content/60">No connections in the last 7 days</p>
            </div>
            {% endif %}
        </div>
    </div>
    <div class="card bg-base-100 border border-base-300 shadow-sm">
        <div class="card-body p-5">
            <h2 class="card-title text-base font-semibold text-balance">OS Distribution</h2>
            {% if os_data and os_data|sum > 0 %}
            <div class="relative h-72">
                <canvas id="osChart" role="img" aria-label="Operating system distribution: {% for i in range(os_labels|length) %}{{ os_labels[i] }}: {{ os_data[i] }}{{ ', ' if not loop.last }}{% endfor %}"></canvas>
            </div>
            <table class="sr-only">
                <caption>Devices by operating system</caption>
                <thead><tr><th scope="col">OS</th><th scope="col">Devices</th></tr></thead>
                <tbody>
                    {% for i in range(os_labels|length) %}
                    <tr><td>{{ os_labels[i] }}</td><td>{{ os_data[i] }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="h-72 flex flex-col items-center justify-center text-center">
                <i data-lucide="pie-chart" class="w-10 h-10 opacity-30 mb-2" aria-hidden="true"></i>
                <p class="text-sm text-base-content/60">No devices yet</p>
            </div>
            {% endif %}
        </div>
    </div>
</div>

<!-- Recent Devices -->
<div class="card bg-base-100 border border-base-300 shadow-sm">
    <div class="card-body p-0">
        <div class="p-5 flex justify-between items-center border-b border-base-300">
            <h2 class="card-title text-base font-semibold text-balance">Recent Devices</h2>
            <a href="{{ url_for('web_devices') }}" class="btn btn-outline btn-sm">View All</a>
        </div>
        {% if devices %}
        <div class="overflow-x-auto">
            <table class="table table-zebra w-full">
                <thead>
                    <tr>
                        <th scope="col">ID</th>
                        <th scope="col">Hostname</th>
                        <th scope="col" class="hidden md:table-cell">User</th>
                        <th scope="col" class="hidden md:table-cell">OS</th>
                        <th scope="col" class="hidden md:table-cell">IP</th>
                        <th scope="col">Status</th>
                        <th scope="col" class="hidden md:table-cell">Last Seen</th>
                        <th scope="col">Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for d in devices[:10] %}
                    <tr class="hover">
                        <td><span class="font-mono font-semibold text-base-content tabular-nums">{{ d.id }}</span></td>
                        <td>{{ d.hostname or '-' }}</td>
                        <td class="hidden md:table-cell">{{ d.username or '-' }}</td>
                        <td class="hidden md:table-cell">{{ d.os_short }}</td>
                        <td class="hidden md:table-cell"><span class="font-mono tabular-nums">{{ d.ip or '-' }}</span></td>
                        <td class="js-device-status" data-device-id="{{ d.id }}">
                            {% if d.online %}
                            <span class="badge badge-success gap-1 text-xs font-semibold">
                                <span class="w-1.5 h-1.5 rounded-full bg-success-content motion-safe:animate-pulse"></span>
                                Online
                            </span>
                            {% else %}
                            <span class="badge badge-ghost text-xs font-semibold">Offline</span>
                            {% endif %}
                        </td>
                        <td class="hidden md:table-cell"><span class="font-mono tabular-nums">{{ d.last_seen_str }}</span></td>
                        <td>
                            <button class="btn btn-primary btn-sm" onclick='connectTo({{ d.id | tojson }})' aria-label="Connect to device {{ d.id }}">
                                <i data-lucide="link" class="w-4 h-4" aria-hidden="true"></i> Connect
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="py-16 text-center">
            <i data-lucide="monitor-off" class="w-12 h-12 opacity-40 mx-auto mb-3" aria-hidden="true"></i>
            <h2 class="font-semibold text-lg">No devices yet</h2>
            <p class="text-sm text-base-content/70 mt-1 max-w-md mx-auto">Devices that sign in to this server will appear here automatically.</p>
        </div>
        {% endif %}
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
function connectTo(id) {
    window.location.href = 'rustdesk://connection/new/' + id;
}

// Build the dashboard charts and register them so the theme toggle can
// re-color them in place (P6). getChartThemeColors() resolves DaisyUI tokens
// for the current theme; each chart carries a __recolor(colors) method that
// re-applies them, invoked by toggleTheme() after a switch.
const chartColors = window.getChartThemeColors();

// Connections Chart — canvas is only rendered when there's data (see the
// empty-state branch in the template above).
const connCanvas = document.getElementById('connectionsChart');
if (connCanvas) {
    const connectionsChart = new Chart(connCanvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: {{ chart_labels | tojson }},
            datasets: [{
                label: 'Connections',
                data: {{ chart_data | tojson }},
                borderColor: chartColors.primary,
                backgroundColor: chartColors.primaryFill,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: chartColors.grid }, ticks: { color: chartColors.text } },
                x: { grid: { color: chartColors.grid }, ticks: { color: chartColors.text } }
            }
        }
    });
    connectionsChart.__recolor = function(colors) {
        this.data.datasets[0].borderColor = colors.primary;
        this.data.datasets[0].backgroundColor = colors.primaryFill;
        this.options.scales.y.grid.color = colors.grid;
        this.options.scales.y.ticks.color = colors.text;
        this.options.scales.x.grid.color = colors.grid;
        this.options.scales.x.ticks.color = colors.text;
    };
    window.__charts.push(connectionsChart);
}

// OS Chart
const osCanvas = document.getElementById('osChart');
if (osCanvas) {
    const osChart = new Chart(osCanvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: {{ os_labels | tojson }},
            datasets: [{
                data: {{ os_data | tojson }},
                backgroundColor: chartColors.palette
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: chartColors.text } } }
        }
    });
    osChart.__recolor = function(colors) {
        this.data.datasets[0].backgroundColor = colors.palette;
        this.options.plugins.legend.labels.color = colors.text;
    };
    window.__charts.push(osChart);
}

// ============ Live polling ============
// Refresh KPIs, chart series and device online/offline in place every 20s so
// the "monitoring" dashboard actually stays current without a full reload.
// Pauses while the tab is hidden (saves the server pointless queries) and
// resumes — refreshing immediately — when it becomes visible again. On a
// fetch failure the live indicator flips to a muted "Reconnecting…" state
// instead of silently going stale.
(function() {
    const REFRESH_MS = 20000;
    let timer = null;
    let lastOkTs = Date.now();

    const dot = document.getElementById('liveDot');
    const statusEl = document.getElementById('liveStatus');
    const updatedEl = document.getElementById('lastUpdated');

    function setLive(isLive) {
        if (!dot || !statusEl) { return; }
        dot.classList.toggle('is-live', isLive);
        dot.style.background = isLive ? 'oklch(var(--su))' : 'oklch(var(--wa))';
        statusEl.textContent = isLive ? 'Live' : 'Reconnecting…';
    }

    function renderUpdated() {
        if (!updatedEl) { return; }
        const secs = Math.round((Date.now() - lastOkTs) / 1000);
        updatedEl.textContent = secs < 5 ? 'just now' : (secs < 60 ? secs + 's ago' : Math.floor(secs / 60) + 'm ago');
    }
    setInterval(renderUpdated, 5000);

    function findChart(canvasId) {
        const c = document.getElementById(canvasId);
        if (!c) { return null; }
        return (window.__charts || []).find(ch => ch.canvas === c) || null;
    }

    function applyData(data) {
        // KPIs
        document.querySelectorAll('[data-kpi]').forEach(el => {
            const v = data.stats[el.dataset.kpi];
            if (v != null && el.textContent !== String(v)) { el.textContent = v; }
        });
        // Connections line chart
        const line = findChart('connectionsChart');
        if (line) {
            line.data.labels = data.chart_labels;
            line.data.datasets[0].data = data.chart_data;
            line.update('none');
        }
        // OS doughnut
        const os = findChart('osChart');
        if (os) {
            os.data.labels = data.os_labels;
            os.data.datasets[0].data = data.os_data;
            os.update('none');
        }
        // Device online/offline badges
        const onlineBadge = '<span class="badge badge-success gap-1 text-xs font-semibold"><span class="w-1.5 h-1.5 rounded-full bg-success-content motion-safe:animate-pulse"></span>Online</span>';
        const offlineBadge = '<span class="badge badge-ghost text-xs font-semibold">Offline</span>';
        document.querySelectorAll('.js-device-status').forEach(cell => {
            const isOnline = !!(data.device_online && data.device_online[cell.dataset.deviceId]);
            const want = isOnline ? onlineBadge : offlineBadge;
            if (cell.innerHTML.trim() !== want) { cell.innerHTML = want; }
        });
    }

    function refresh() {
        fetch('/api/dashboard/stats', { headers: { 'Accept': 'application/json' } })
            .then(r => { if (!r.ok) { throw new Error(r.status); } return r.json(); })
            .then(data => {
                applyData(data);
                lastOkTs = Date.now();
                renderUpdated();
                setLive(true);
            })
            .catch(() => setLive(false));
    }

    function start() { if (!timer) { timer = setInterval(refresh, REFRESH_MS); } }
    function stop() { if (timer) { clearInterval(timer); timer = null; } }

    document.addEventListener('visibilitychange', function() {
        if (document.hidden) { stop(); }
        else { refresh(); start(); }
    });
    start();
})();
</script>
{% endblock %}
'''

DEVICES_HTML = r'''
{% extends "base" %}
{% block content %}
<div class="flex justify-between items-center mb-6">
    <h1 class="text-2xl font-bold text-base-content text-balance">Devices</h1>
    <button class="btn btn-primary" onclick="this.classList.add('btn-disabled');this.disabled=true;this.innerHTML='<span class=&quot;loading loading-spinner loading-sm&quot; aria-hidden=&quot;true&quot;></span> Refreshing…';location.reload();">
        <i data-lucide="rotate-cw" class="w-4 h-4 mr-2" aria-hidden="true"></i>Refresh
    </button>
</div>

<div class="card bg-base-100 border border-base-300 shadow-sm">
    <div class="card-body p-6">
        {% if devices %}
        <div class="overflow-x-auto">
            <table id="devicesTable" class="table table-zebra w-full">
                <thead>
                    <tr>
                        <th scope="col">ID</th>
                        <th scope="col">Hostname</th>
                        <th scope="col">Username</th>
                        <th scope="col">OS</th>
                        <th scope="col">IP Address</th>
                        <th scope="col">Version</th>
                        <th scope="col">Status</th>
                        <th scope="col">Last Seen</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for d in devices %}
                    <tr class="hover">
                        <td><span class="font-mono font-semibold text-base-content tabular-nums">{{ d.id }}</span></td>
                        <td>{{ d.hostname or '-' }}</td>
                        <td>{{ d.username or '-' }}</td>
                        <td>{{ d.os_short }}</td>
                        <td><span class="font-mono tabular-nums">{{ d.ip or '-' }}</span></td>
                        <td><span class="font-mono tabular-nums">{{ d.version or '-' }}</span></td>
                        <td>
                            {% if d.online %}
                            <span class="badge badge-success gap-1 text-xs font-semibold">
                                <span class="w-1.5 h-1.5 rounded-full bg-success-content motion-safe:animate-pulse"></span>
                                Online
                            </span>
                            {% elif not d.last_seen_iso %}
                            <span class="badge badge-outline text-xs font-semibold" title="This device has registered but never reported its status">Never seen</span>
                            {% else %}
                            <span class="badge badge-ghost text-xs font-semibold">Offline</span>
                            {% endif %}
                        </td>
                        <td data-order="{{ d.last_seen_iso }}"><span class="font-mono tabular-nums">{{ d.last_seen_str }}</span></td>
                        <td class="flex gap-1">
                            <button class="btn btn-primary btn-sm" onclick='connectTo({{ d.id | tojson }})' aria-label="Connect to device {{ d.id }}">
                                <i data-lucide="link" class="w-4 h-4 mr-1" aria-hidden="true"></i>Connect
                            </button>
                            <button class="btn btn-outline btn-sm btn-square" onclick='showDetails({{ d.id | tojson }})' title="Details" aria-label="View details for device {{ d.id }}">
                                <i data-lucide="info" class="w-4 h-4" aria-hidden="true"></i>
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="py-16 text-center">
            <i data-lucide="monitor-off" class="w-12 h-12 opacity-40 mx-auto mb-3" aria-hidden="true"></i>
            <h2 class="font-semibold text-lg">No devices found</h2>
            <p class="text-sm text-base-content/70 mt-1 max-w-md mx-auto">Devices appear here once they connect to this server. If you're searching, try a different term.</p>
        </div>
        {% endif %}
    </div>
</div>

<!-- Device Details Modal -->
<dialog id="detailsModal" class="modal">
    <div class="modal-box">
        <form method="dialog">
            <button class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2" aria-label="Close modal">✕</button>
        </form>
        <h3 class="font-bold text-lg text-balance mb-4">Device Details</h3>
        <div id="detailsBody">
        </div>
    </div>
    <form method="dialog" class="modal-backdrop">
        <button>close</button>
    </form>
</dialog>
{% endblock %}

{% block scripts %}
<script>
$(document).ready(function() {
    if ($.fn.DataTable && $('#devicesTable tbody tr').length) {
    window.initDataTable('#devicesTable', {
        order: [[7, 'desc']],
        pageLength: 25,
        search: {
            search: {{ search_query | tojson }}
        },
        language: {
            search: "Search:",
            lengthMenu: "Show _MENU_ devices"
        }
    });
    }
});

function connectTo(id) {
    window.location.href = 'rustdesk://connection/new/' + id;
}

const devices = {{ devices | tojson }};

// HTML-escape values before innerHTML interpolation: device fields (hostname
// etc.) are client-supplied and old DB rows predate server-side sanitization.
function esc(s) {
    return String(s ?? '').replace(/[&<>"'`]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c]));
}

function showDetails(id) {
    const d = devices.find(x => x.id === id);
    if (!d) return;
    document.getElementById('detailsBody').innerHTML = `
        <div class="overflow-x-auto">
            <table class="table table-compact w-full text-sm">
                <tbody>
                    <tr class="border-b border-base-200"><th class="w-24 text-base-content/70">ID</th><td><code class="font-mono font-semibold text-base-content tabular-nums">${esc(d.id)}</code></td></tr>
                    <tr class="border-b border-base-200"><th class="text-base-content/70">Hostname</th><td>${esc(d.hostname) || '-'}</td></tr>
                    <tr class="border-b border-base-200"><th class="text-base-content/70">Username</th><td>${esc(d.username) || '-'}</td></tr>
                    <tr class="border-b border-base-200"><th class="text-base-content/70">OS</th><td>${esc(d.os) || '-'}</td></tr>
                    <tr class="border-b border-base-200"><th class="text-base-content/70">IP</th><td><span class="font-mono tabular-nums">${esc(d.ip) || '-'}</span></td></tr>
                    <tr class="border-b border-base-200"><th class="text-base-content/70">CPU</th><td>${esc(d.cpu) || '-'}</td></tr>
                    <tr class="border-b border-base-200"><th class="text-base-content/70">Memory</th><td>${esc(d.memory) || '-'}</td></tr>
                    <tr class="border-b border-base-200"><th class="text-base-content/70">Version</th><td><span class="font-mono tabular-nums">${esc(d.version) || '-'}</span></td></tr>
                    <tr><th class="text-base-content/70">Last Seen</th><td><span class="font-mono tabular-nums">${esc(d.last_seen_str)}</span></td></tr>
                </tbody>
            </table>
        </div>
        <button id="detailsConnectBtn" class="btn btn-primary w-full mt-4" aria-label="Connect to device">
            <i data-lucide="link" class="w-4 h-4 mr-2" aria-hidden="true"></i>Connect
        </button>
    `;
    document.getElementById('detailsConnectBtn').addEventListener('click', () => connectTo(d.id));
    document.getElementById('detailsModal').showModal();
    if (window.lucide) {
        lucide.createIcons();
    }
}
</script>
{% endblock %}
'''

USERS_HTML = r'''
{% extends "base" %}
{% block content %}
<div class="flex justify-between items-center mb-6">
    <h1 class="text-2xl font-bold text-base-content text-balance">Users</h1>
    <button class="btn btn-primary" onclick="document.getElementById('addUserModal').showModal()">
        <i data-lucide="user-plus" class="w-4 h-4 mr-2" aria-hidden="true"></i>Add User
    </button>
</div>

<div class="card bg-base-100 border border-base-300 shadow-sm">
    <div class="card-body p-6">
        {% if users %}
        <div class="overflow-x-auto">
            <table id="usersTable" class="table table-zebra w-full">
                <thead>
                    <tr>
                        <th scope="col" class="hidden md:table-cell">ID</th>
                        <th scope="col">Username</th>
                        <th scope="col" class="hidden sm:table-cell">Email</th>
                        <th scope="col">Role</th>
                        <th scope="col">Source</th>
                        <th scope="col">Status</th>
                        <th scope="col" class="hidden md:table-cell">Created</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for u in users %}
                    <tr class="hover">
                        <td class="hidden md:table-cell"><span class="tabular-nums">{{ u.id }}</span></td>
                        <td class="font-medium flex items-center gap-2">
                            <i data-lucide="user" class="w-4 h-4 text-base-content/40" aria-hidden="true"></i>
                            {{ u.username }}
                        </td>
                        <td class="hidden sm:table-cell">{{ u.email or '-' }}</td>
                        <td>
                            {% if u.is_admin %}
                            <span class="badge badge-primary text-xs font-semibold">Admin</span>
                            {% else %}
                            <span class="badge badge-ghost text-xs font-semibold">User</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if u.auth_source == 'ldap' %}
                            <span class="badge badge-outline badge-info text-xs font-semibold">Domain</span>
                            {% else %}
                            <span class="badge badge-outline text-xs font-semibold">Local</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if u.status == 1 %}
                            <span class="badge badge-success text-xs font-semibold">Active</span>
                            {% else %}
                            <span class="badge badge-error text-xs font-semibold">Disabled</span>
                            {% endif %}
                        </td>
                        <td class="hidden md:table-cell"><span class="text-sm text-base-content/70 tabular-nums">{{ u.created_at }}</span></td>
                        <td>
                            <button class="btn btn-sm btn-ghost text-error {{ 'btn-disabled opacity-50' if u.username == 'admin' else '' }}" onclick='deleteUser({{ u.id }}, {{ u.username | tojson }})' {{ 'disabled' if u.username == 'admin' else '' }} aria-label="Delete user {{ u.username }}" title="{{ 'The built-in admin account cannot be deleted' if u.username == 'admin' else 'Delete user' }}">
                                <i data-lucide="trash-2" class="w-5 h-5" aria-hidden="true"></i>
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="py-16 text-center">
            <i data-lucide="users" class="w-12 h-12 opacity-40 mx-auto mb-3" aria-hidden="true"></i>
            <h2 class="font-semibold text-lg">No users yet</h2>
            <p class="text-sm text-base-content/70 mt-1 max-w-md mx-auto">Use the "Add User" button above to create the first account.</p>
        </div>
        {% endif %}
    </div>
</div>

<!-- Add User Modal -->
<dialog id="addUserModal" class="modal" aria-labelledby="addUserModalTitle">
    <div class="modal-box">
        <form method="dialog">
            <button class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2" aria-label="Close modal">✕</button>
        </form>
        <h2 id="addUserModalTitle" class="font-bold text-lg text-balance mb-4">Add User</h2>
        <form action="{{ url_for('web_add_user') }}" method="POST">
            <div class="form-control w-full mb-4">
                <label class="label" for="add-username"><span class="label-text font-semibold">Username</span></label>
                <input type="text" id="add-username" class="input input-bordered w-full" name="username" placeholder="Username… e.g. jdoe" required autocomplete="username" spellcheck="false">
            </div>
            <div class="form-control w-full mb-4">
                <label class="label" for="add-email"><span class="label-text font-semibold">Email</span></label>
                <input type="email" id="add-email" class="input input-bordered w-full" name="email" placeholder="Email… e.g. jdoe@company.com" autocomplete="email" spellcheck="false">
            </div>
            <div class="form-control w-full mb-4">
                <label class="label" for="add-password"><span class="label-text font-semibold">Password</span></label>
                <input type="password" id="add-password" class="input input-bordered w-full" name="password" placeholder="Password…" required autocomplete="new-password" spellcheck="false">
            </div>
            <div class="form-control w-full mb-6">
                <label class="label cursor-pointer justify-start gap-3" for="add-is-admin">
                    <input type="checkbox" class="checkbox checkbox-primary" name="is_admin" id="add-is-admin">
                    <span class="label-text font-semibold">Administrator</span>
                </label>
            </div>
            <div class="flex justify-end gap-3 mt-4">
                <button type="button" class="btn btn-ghost" onclick="document.getElementById('addUserModal').close()">Cancel</button>
                <button type="submit" class="btn btn-primary" data-loading-text="Adding…">Add User</button>
            </div>
        </form>
    </div>
    <form method="dialog" class="modal-backdrop">
        <button>close</button>
    </form>
</dialog>
{% endblock %}

{% block scripts %}
<script>
$(document).ready(function() {
    if ($.fn.DataTable && $('#usersTable tbody tr').length) {
        window.initDataTable('#usersTable', {});
    }
});

function deleteUser(id, username) {
    window.confirmDialog(`Delete user "${username}"? This cannot be undone.`, () => {
        fetch('/api/admin/users/' + id, { method: 'DELETE' })
            .then(res => {
                if (!res.ok) { throw new Error('Server returned ' + res.status); }
                sessionStorage.setItem('flashToast', JSON.stringify({ m: 'User "' + username + '" deleted', t: 'success' }));
                location.reload();
            })
            .catch(err => window.showToast('Failed to delete user: ' + err.message, 'error'));
    }, { confirmLabel: 'Delete' });
}
</script>
{% endblock %}
'''

LOGS_HTML = r'''
{% extends "base" %}
{% block content %}
<div class="flex flex-wrap justify-between items-center gap-3 mb-6">
    <h1 class="text-2xl font-bold text-base-content text-balance">Audit Logs</h1>
    <div class="join">
        <button class="btn join-item btn-sm {{ 'btn-primary text-primary-content' if log_type == 'all' else 'btn-outline' }}" aria-current="{{ 'true' if log_type == 'all' else 'false' }}" onclick="location.href='?type=all'">All</button>
        <button class="btn join-item btn-sm {{ 'btn-primary text-primary-content' if log_type == 'conn' else 'btn-outline' }}" aria-current="{{ 'true' if log_type == 'conn' else 'false' }}" onclick="location.href='?type=conn'">Connections</button>
        <button class="btn join-item btn-sm {{ 'btn-primary text-primary-content' if log_type == 'file' else 'btn-outline' }}" aria-current="{{ 'true' if log_type == 'file' else 'false' }}" onclick="location.href='?type=file'">Files</button>
        <button class="btn join-item btn-sm {{ 'btn-primary text-primary-content' if log_type == 'alarm' else 'btn-outline' }}" aria-current="{{ 'true' if log_type == 'alarm' else 'false' }}" onclick="location.href='?type=alarm'">Alarms</button>
    </div>
</div>

<div class="card bg-base-100 border border-base-300 shadow-sm">
    <div class="card-body p-6">
        {% if logs %}
        <div class="overflow-x-auto">
            <table id="logsTable" class="table table-zebra w-full">
                <thead>
                    <tr>
                        <th scope="col">Time</th>
                        <th scope="col">Type</th>
                        <th scope="col">Device ID</th>
                        <th scope="col">Peer ID</th>
                        <th scope="col">Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr class="hover">
                        <td><span class="text-sm text-base-content/70 tabular-nums">{{ log.created_at }}</span></td>
                        <td>
                            {% if log.type == 'conn' %}
                            <span class="badge badge-accent text-xs font-semibold">conn</span>
                            {% elif log.type == 'file' %}
                            <span class="badge badge-warning text-xs font-semibold">file</span>
                            {% elif log.type == 'alarm' %}
                            <span class="badge badge-error text-xs font-semibold">alarm</span>
                            {% else %}
                            <span class="badge badge-ghost text-xs font-semibold">{{ log.type|title if log.type else 'Unknown' }}</span>
                            {% endif %}
                        </td>
                        <td><code class="font-mono text-sm text-base-content/70 tabular-nums">{{ log.device_id or '-' }}</code></td>
                        <td><code class="font-mono text-sm text-base-content/70 tabular-nums">{{ log.peer_id or '-' }}</code></td>
                        <td>{{ log.action or '-' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="py-16 text-center">
            <i data-lucide="scroll-text" class="w-12 h-12 opacity-40 mx-auto mb-3" aria-hidden="true"></i>
            <h2 class="font-semibold text-lg">No logs yet</h2>
            <p class="text-sm text-base-content/70 mt-1 max-w-md mx-auto">Audit events such as connections, file transfers, and alarms will appear here as devices are used.</p>
        </div>
        {% endif %}
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
$(document).ready(function() {
    if ($.fn.DataTable && $('#logsTable tbody tr').length) {
        window.initDataTable('#logsTable', {
            order: [[0, 'desc']],
            pageLength: 50
        });
    }
});
</script>
{% endblock %}
'''

SETTINGS_HTML = r'''
{% extends "base" %}
{% block content %}
<h1 class="text-2xl font-bold text-base-content text-balance mb-6">Settings</h1>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="space-y-6">
        <div class="card bg-base-100 border border-base-300 shadow-sm">
            <div class="card-body p-6">
                <h2 class="card-title text-base font-semibold text-balance border-b border-base-200 pb-3 mb-4"><i data-lucide="server" class="text-primary w-5 h-5 mr-2" aria-hidden="true"></i>Server Configuration</h2>
                <div class="form-control w-full mb-4">
                    <label class="label" for="settings-id-server"><span class="label-text text-base-content/70">ID Server</span></label>
                    <input type="text" id="settings-id-server" class="input input-bordered w-full bg-base-200 tabular-nums" value="{{ id_server }}" disabled>
                </div>
                <div class="form-control w-full mb-4">
                    <label class="label" for="settings-relay-server"><span class="label-text text-base-content/70">Relay Server</span></label>
                    <input type="text" id="settings-relay-server" class="input input-bordered w-full bg-base-200 tabular-nums" value="{{ relay_server }}" disabled>
                </div>
                <div class="form-control w-full">
                    <label class="label" for="settings-api-server"><span class="label-text text-base-content/70">API Server</span></label>
                    <input type="text" id="settings-api-server" class="input input-bordered w-full bg-base-200" value="https://{{ request.host }}" disabled>
                </div>
            </div>
        </div>
        
        <div class="card bg-base-100 border border-base-300 shadow-sm">
            <div class="card-body p-6">
                <h2 class="card-title text-base font-semibold text-balance border-b border-base-200 pb-3 mb-4"><i data-lucide="info" class="text-primary w-5 h-5 mr-2" aria-hidden="true"></i>System Info</h2>
                <div class="overflow-x-auto">
                    <table class="table table-compact w-full text-sm">
                        <tbody>
                            <tr class="border-b border-base-200">
                                <td class="text-base-content/70">LDAP Library</td>
                                <td class="text-right">
                                    {% if ldap_available %}
                                    <span class="badge badge-success text-xs font-semibold">Installed</span>
                                    {% else %}
                                    <span class="badge badge-ghost text-xs font-semibold">Not installed</span>
                                    {% endif %}
                                </td>
                            </tr>
                            <tr>
                                <td class="text-base-content/70">LDAP Status</td>
                                <td class="text-right">
                                    {% if ldap_config.get('enabled') %}
                                    <span class="badge badge-success text-xs font-semibold">Enabled</span>
                                    {% else %}
                                    <span class="badge badge-ghost text-xs font-semibold">Disabled</span>
                                    {% endif %}
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="card bg-base-100 border border-base-300 shadow-sm mt-6">
            <div class="card-body p-6">
                <h2 class="card-title text-base font-semibold text-balance border-b border-base-200 pb-3 mb-4">
                    <i data-lucide="globe" class="text-primary w-5 h-5 mr-2" aria-hidden="true"></i>Global Client Settings
                </h2>
                
                <form action="/settings/global" method="POST" id="globalSettingsForm">
                    <fieldset class="border-0 p-0 m-0">
                    <legend class="text-sm font-semibold text-base-content/70 mb-3 p-0">General Settings</legend>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                        <div class="form-control w-full">
                            <label class="label" for="globalTheme">
                                <span class="label-text font-semibold">Client Theme</span>
                            </label>
                            <select class="select select-bordered w-full" name="theme" id="globalTheme">
                                <option value="" {% if not global_settings.get('theme') %}selected{% endif %}>Not Enforced (User Choice)</option>
                                <option value="light" {% if global_settings.get('theme') == 'light' %}selected{% endif %}>Light Mode</option>
                                <option value="dark" {% if global_settings.get('theme') == 'dark' %}selected{% endif %}>Dark Mode</option>
                            </select>
                        </div>
                        
                        <div class="form-control w-full">
                            <label class="label" for="globalLanDiscovery">
                                <span class="label-text font-semibold">LAN Discovery</span>
                            </label>
                            <select class="select select-bordered w-full" name="enable-lan-discovery" id="globalLanDiscovery">
                                <option value="" {% if not global_settings.get('enable-lan-discovery') %}selected{% endif %}>Not Enforced</option>
                                <option value="Y" {% if global_settings.get('enable-lan-discovery') == 'Y' %}selected{% endif %}>Force Enabled</option>
                                <option value="N" {% if global_settings.get('enable-lan-discovery') == 'N' %}selected{% endif %}>Force Disabled</option>
                            </select>
                        </div>
                    </div>
                    </fieldset>

                    <fieldset class="border-0 p-0 m-0 border-t border-base-200 pt-4">
                    <legend class="text-sm font-semibold text-base-content/70 mb-3 p-0">Security Settings</legend>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div class="form-control w-full">
                            <label class="label" for="globalApproveMode">
                                <span class="label-text font-semibold">Incoming Connection Approval Mode</span>
                            </label>
                            <select class="select select-bordered w-full" name="approve-mode" id="globalApproveMode">
                                <option value="" {% if not global_settings.get('approve-mode') %}selected{% endif %}>Not Enforced</option>
                                <option value="click" {% if global_settings.get('approve-mode') == 'click' %}selected{% endif %}>Click to Accept</option>
                                <option value="password" {% if global_settings.get('approve-mode') == 'password' %}selected{% endif %}>Password Access</option>
                                <option value="both" {% if global_settings.get('approve-mode') == 'both' %}selected{% endif %}>Both (Accept or Password)</option>
                            </select>
                        </div>
                        
                        <div class="form-control w-full">
                            <label class="label" for="globalVerificationMethod">
                                <span class="label-text font-semibold">Verification Method</span>
                            </label>
                            <select class="select select-bordered w-full" name="verification-method" id="globalVerificationMethod">
                                <option value="" {% if not global_settings.get('verification-method') %}selected{% endif %}>Not Enforced</option>
                                <option value="use-both" {% if global_settings.get('verification-method') == 'use-both' %}selected{% endif %}>Both (Temporary & Permanent)</option>
                                <option value="use-temporary" {% if global_settings.get('verification-method') == 'use-temporary' %}selected{% endif %}>Only Temporary Password</option>
                                <option value="use-permanent" {% if global_settings.get('verification-method') == 'use-permanent' %}selected{% endif %}>Only Permanent Password</option>
                            </select>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div class="form-control w-full">
                            <label class="label" for="globalAllowConfigMod">
                                <span class="label-text font-semibold">Allow Remote Config Modification</span>
                            </label>
                            <select class="select select-bordered w-full" name="allow-remote-config-modification" id="globalAllowConfigMod">
                                <option value="" {% if not global_settings.get('allow-remote-config-modification') %}selected{% endif %}>Not Enforced</option>
                                <option value="Y" {% if global_settings.get('allow-remote-config-modification') == 'Y' %}selected{% endif %}>Force Enabled</option>
                                <option value="N" {% if global_settings.get('allow-remote-config-modification') == 'N' %}selected{% endif %}>Force Disabled</option>
                            </select>
                        </div>
                        
                        <div class="form-control w-full">
                            <label class="label" for="globalAllowNumericOtp">
                                <span class="label-text font-semibold">Allow Numeric One-Time Password</span>
                            </label>
                            <select class="select select-bordered w-full" name="allow-numeric-one-time-password" id="globalAllowNumericOtp">
                                <option value="" {% if not global_settings.get('allow-numeric-one-time-password') %}selected{% endif %}>Not Enforced</option>
                                <option value="Y" {% if global_settings.get('allow-numeric-one-time-password') == 'Y' %}selected{% endif %}>Force Enabled</option>
                                <option value="N" {% if global_settings.get('allow-numeric-one-time-password') == 'N' %}selected{% endif %}>Force Disabled</option>
                            </select>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        <div class="form-control w-full">
                            <label class="label" for="globalEnableKeyboard">
                                <span class="label-text font-semibold">Keyboard Control</span>
                            </label>
                            <select class="select select-bordered w-full select-sm" name="enable-keyboard" id="globalEnableKeyboard">
                                <option value="" {% if not global_settings.get('enable-keyboard') %}selected{% endif %}>Not Enforced</option>
                                <option value="Y" {% if global_settings.get('enable-keyboard') == 'Y' %}selected{% endif %}>Force On</option>
                                <option value="N" {% if global_settings.get('enable-keyboard') == 'N' %}selected{% endif %}>Force Off</option>
                            </select>
                        </div>

                        <div class="form-control w-full">
                            <label class="label" for="globalEnableClipboard">
                                <span class="label-text font-semibold">Clipboard Sharing</span>
                            </label>
                            <select class="select select-bordered w-full select-sm" name="enable-clipboard" id="globalEnableClipboard">
                                <option value="" {% if not global_settings.get('enable-clipboard') %}selected{% endif %}>Not Enforced</option>
                                <option value="Y" {% if global_settings.get('enable-clipboard') == 'Y' %}selected{% endif %}>Force On</option>
                                <option value="N" {% if global_settings.get('enable-clipboard') == 'N' %}selected{% endif %}>Force Off</option>
                            </select>
                        </div>

                        <div class="form-control w-full">
                            <label class="label" for="globalEnableFileTransfer">
                                <span class="label-text font-semibold">File Transfer</span>
                            </label>
                            <select class="select select-bordered w-full select-sm" name="enable-file-transfer" id="globalEnableFileTransfer">
                                <option value="" {% if not global_settings.get('enable-file-transfer') %}selected{% endif %}>Not Enforced</option>
                                <option value="Y" {% if global_settings.get('enable-file-transfer') == 'Y' %}selected{% endif %}>Force On</option>
                                <option value="N" {% if global_settings.get('enable-file-transfer') == 'N' %}selected{% endif %}>Force Off</option>
                            </select>
                        </div>

                        <div class="form-control w-full">
                            <label class="label" for="globalEnableAudio">
                                <span class="label-text font-semibold">Audio Transmission</span>
                            </label>
                            <select class="select select-bordered w-full select-sm" name="enable-audio" id="globalEnableAudio">
                                <option value="" {% if not global_settings.get('enable-audio') %}selected{% endif %}>Not Enforced</option>
                                <option value="Y" {% if global_settings.get('enable-audio') == 'Y' %}selected{% endif %}>Force On</option>
                                <option value="N" {% if global_settings.get('enable-audio') == 'N' %}selected{% endif %}>Force Off</option>
                            </select>
                        </div>
                    </div>
                    </fieldset>

                    <div class="flex flex-wrap gap-3">
                        <button type="submit" class="btn btn-primary" data-loading-text="Applying…">
                            <i data-lucide="save" class="w-4 h-4 mr-1" aria-hidden="true"></i>Apply Global Settings
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="card bg-base-100 border border-base-300 shadow-sm">
        <div class="card-body p-6">
            <div class="flex flex-wrap justify-between items-center gap-2 border-b border-base-200 pb-3 mb-4">
                <h2 class="card-title text-base font-semibold text-balance"><i data-lucide="network" class="text-primary w-5 h-5 mr-2" aria-hidden="true"></i>LDAP / Active Directory</h2>
                <button type="button" class="btn btn-outline btn-sm" onclick="testLdap()">
                    <i data-lucide="plug" class="w-4 h-4 mr-1" aria-hidden="true"></i>Auto-Discover & Test
                </button>
            </div>

            <div id="ldapTestResult" class="alert hidden mb-4 shadow-sm" aria-live="polite"></div>

            <form action="{{ url_for('web_save_ldap') }}" method="POST" id="ldapForm">

                <div class="form-control w-full mb-4">
                    <label class="label" for="ldapServer"><span class="label-text font-semibold">AD Server Address</span></label>
                    <input type="text" class="input input-bordered w-full font-mono text-sm" name="ldap_server" id="ldapServer" placeholder="ldap://192.168.1.100… e.g. ldap://dc.company.local" value="{{ ldap_config.get('server', '') }}" autocomplete="off" spellcheck="false" required>
                    <span class="label-text-alt text-base-content/70 mt-1 block">IP address or domain of the Domain Controller</span>
                </div>
                <div class="form-control w-full mb-4">
                    <label class="label" for="ldapUser"><span class="label-text font-semibold">Service Account (Username)</span></label>
                    <input type="text" class="input input-bordered w-full font-mono text-sm" name="ldap_bind_dn" id="ldapUser" placeholder="admin@domain.local… e.g. bind_user@company.local" value="{{ ldap_config.get('bind_dn', '') }}" autocomplete="off" spellcheck="false" required>
                    <span class="label-text-alt text-base-content/70 mt-1 block">UPN (user@domain.local) or traditional DOMAIN\user</span>
                </div>
                <div class="form-control w-full mb-4">
                    <label class="label" for="ldapPass"><span class="label-text font-semibold">Password</span></label>
                    <input type="password" class="input input-bordered w-full" name="ldap_bind_password" id="ldapPass" placeholder="Password…" autocomplete="off" spellcheck="false" data-has-saved="{{ 'true' if ldap_config.get('bind_password') else 'false' }}">
                    <span class="label-text-alt text-base-content/70 mt-1 block">Only needed if changing existing configuration — leave blank to keep the saved password</span>
                </div>

                <div class="form-control w-full mb-4">
                    <label class="label" for="ldapBaseDn"><span class="label-text font-semibold">Search Base DN</span></label>
                    <input type="text" class="input input-bordered w-full font-mono text-sm" name="ldap_base_dn" id="ldapBaseDn" placeholder="OU=Staff,DC=company,DC=local… (empty = auto-discover domain root)" value="{{ ldap_config.get('base_dn', '') }}" autocomplete="off" spellcheck="false">
                    <span class="label-text-alt text-base-content/70 mt-1 block">Users are searched only under this DN — point it at a specific OU to limit who can sign in. "Auto-Discover &amp; Test" fills in the domain root when left empty.</span>
                </div>

                <div class="rounded-lg border border-warning/30 bg-warning/5 p-4 mb-6">
                    <p class="text-xs font-semibold text-warning flex items-center gap-1.5 mb-3">
                        <i data-lucide="triangle-alert" class="w-4 h-4" aria-hidden="true"></i>
                        Misconfiguring these two fields can lock domain admins out of the panel
                    </p>
                    <div class="form-control w-full mb-4">
                        <label class="label" for="ldapAdminGroups"><span class="label-text font-semibold">Admin LDAP Groups</span></label>
                        <input type="text" class="input input-bordered w-full" name="ldap_admin_groups" id="ldapAdminGroups" placeholder="Domain Admins, Administrators, RustDesk Admins…" value="{{ ldap_config.get('admin_groups', '') }}" autocomplete="off" spellcheck="false">
                        <span class="label-text-alt text-base-content/70 mt-1 block">Comma-separated list of LDAP groups that map to the local Administrator role (others map to standard User role)</span>
                    </div>

                    <div class="form-control w-full">
                        <label class="label cursor-pointer justify-start gap-3" for="ldapEnabled">
                            <input type="checkbox" class="checkbox checkbox-warning" name="ldap_enabled" id="ldapEnabled" {{ 'checked' if ldap_config.get('enabled') else '' }}>
                            <span class="label-text font-semibold">Enable LDAP Authentication</span>
                        </label>
                    </div>
                </div>

                <div class="flex flex-wrap gap-3">
                    <button type="submit" class="btn btn-primary" data-loading-text="Saving…">
                        <i data-lucide="save" class="w-4 h-4 mr-1" aria-hidden="true"></i>Save Configuration
                    </button>
                </div>
                <p class="text-sm text-base-content/70 mt-3">Domain users appear in the Users list automatically on their first sign-in; admin rights follow LDAP group membership on every sign-in.</p>
            </form>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// Success toast after a settings save (server redirects here with ?saved=…).
document.addEventListener('DOMContentLoaded', function() {
    const params = new URLSearchParams(window.location.search);
    const saved = params.get('saved');
    if (saved) {
        window.showToast(saved === 'ldap' ? 'LDAP configuration saved' : 'Global settings applied', 'success');
        // Strip the query param so a refresh doesn't re-toast.
        history.replaceState(null, '', window.location.pathname);
    }
});

// Tracks whether a Test has succeeded since the LDAP form was last edited —
// gates enabling LDAP without ever having verified the connection (issue: an
// admin could previously type a config and hit Save with Enable checked
// without testing, silently locking non-domain admins out).
let ldapTestPassed = false;

function testLdap() {
    const server = document.getElementById('ldapServer').value;
    const user = document.getElementById('ldapUser').value;
    const passInput = document.getElementById('ldapPass');
    const pass = passInput.value;

    if (!server || !user) {
        window.showToast("Enter the AD Server Address and Service Account first", "warning");
        return;
    }
    if (!pass) {
        window.showToast(passInput.dataset.hasSaved === 'true'
            ? "Re-enter the service account password to test — this always verifies live, not against the saved password."
            : "Enter the service account password first", "warning");
        return;
    }

    const resultDiv = document.getElementById('ldapTestResult');
    resultDiv.className = 'alert alert-info shadow-sm flex items-center gap-2';
    resultDiv.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin" aria-hidden="true"></i>Testing connection and discovering Base DN…';
    resultDiv.classList.remove('hidden');
    if (window.lucide) { lucide.createIcons(); }

    fetch('/api/ldap/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server: server, username: user, password: pass })
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                resultDiv.className = 'alert alert-success shadow-sm flex items-center gap-2';
                resultDiv.innerHTML = '<i data-lucide="check-circle-2" class="w-4 h-4" aria-hidden="true"></i>' + data.message;
                ldapTestPassed = true;
                // Fill the Base DN field only when the admin hasn't chosen one
                // (never overwrite a manually configured OU)
                const baseDnInput = document.getElementById('ldapBaseDn');
                if (data.base_dn && baseDnInput && !baseDnInput.value.trim()) {
                    baseDnInput.value = data.base_dn;
                }
            } else {
                resultDiv.className = 'alert alert-error shadow-sm flex items-center gap-2';
                resultDiv.innerHTML = '<i data-lucide="alert-circle" class="w-4 h-4" aria-hidden="true"></i>' + data.message;
                if (!data.ldap_available) {
                    resultDiv.innerHTML += '<br><small>Install ldap3: <code>pip install ldap3</code></small>';
                }
            }
            if (window.lucide) { lucide.createIcons(); }
        })
        .catch(err => {
            resultDiv.className = 'alert alert-error shadow-sm flex items-center gap-2';
            resultDiv.innerHTML = '<i data-lucide="alert-circle" class="w-4 h-4" aria-hidden="true"></i>Connection test failed: ' + err;
            if (window.lucide) { lucide.createIcons(); }
        });
}

// Warn before navigating away with unsaved changes, on EITHER settings form.
let isFormDirty = false;
[document.getElementById('ldapForm'), document.getElementById('globalSettingsForm')].forEach(form => {
    if (!form) { return; }
    form.querySelectorAll('input:not([type="hidden"]), select').forEach(input => {
        input.addEventListener('input', () => {
            isFormDirty = true;
            if (form.id === 'ldapForm') { ldapTestPassed = false; }
        });
        input.addEventListener('change', () => {
            isFormDirty = true;
            if (form.id === 'ldapForm') { ldapTestPassed = false; }
        });
    });
    form.addEventListener('submit', () => { isFormDirty = false; });
});
window.addEventListener('beforeunload', (e) => {
    if (isFormDirty) {
        e.preventDefault();
        e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
    }
});

// Gate: enabling LDAP without a successful Test this session risks locking
// domain admins out with no warning if the config is wrong. Require explicit
// acknowledgement in that case (never silently blocks the save).
document.getElementById('ldapForm').addEventListener('submit', function(e) {
    if (this.dataset.confirmed === 'true') { return; }
    const enabling = document.getElementById('ldapEnabled').checked;
    if (enabling && !ldapTestPassed) {
        e.preventDefault();
        e.stopPropagation(); // don't let the shared submit-spinner handler
                              // (BASE_HTML, document-level) fire for a submit
                              // we just cancelled pending confirmation
        window.confirmDialog(
            "LDAP Authentication is being enabled without a successful connection test in this session. If the server, service account, or admin groups are wrong, domain admins may not be able to sign in. Save anyway?",
            () => { this.dataset.confirmed = 'true'; this.requestSubmit(); },
            { confirmLabel: 'Save anyway' }
        );
    }
});
</script>
{% endblock %}
'''

MY_DEVICES_HTML = r"""
{% extends "base" %}
{% block content %}
<div class="flex justify-between items-center mb-6">
    <h1 class="text-2xl font-bold text-base-content text-balance">My Devices</h1>
</div>

{% if not devices %}
<div class="card bg-base-100 border border-base-300 shadow-sm">
    <div class="card-body p-10 items-center text-center">
        <i data-lucide="monitor-off" class="w-12 h-12 opacity-40 mb-3" aria-hidden="true"></i>
        <h2 class="font-semibold text-lg">No devices yet</h2>
        <p class="text-base-content/70 max-w-md">Sign in to your account in the RustDesk app on a device — it will appear here and in the address book of all your clients automatically.</p>
    </div>
</div>
{% else %}
<div class="card bg-base-100 border border-base-300 shadow-sm">
    <div class="card-body p-6">
        <div class="overflow-x-auto">
            <table id="myDevicesTable" class="table table-zebra w-full">
                <thead>
                    <tr>
                        <th scope="col">ID</th>
                        <th scope="col">Hostname</th>
                        <th scope="col">Username</th>
                        <th scope="col">OS</th>
                        <th scope="col">IP Address</th>
                        <th scope="col">Password</th>
                        <th scope="col">Status</th>
                        <th scope="col">Last Seen</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for d in devices %}
                    <tr class="hover">
                        <td>
                            <span class="font-mono font-semibold text-base-content tabular-nums">{{ d.id }}</span>
                            <button type="button" class="btn btn-ghost btn-xs btn-square js-copy-id" data-id="{{ d.id }}" title="Copy ID" aria-label="Copy device ID {{ d.id }}">
                                <i data-lucide="copy" class="w-3.5 h-3.5" aria-hidden="true"></i>
                            </button>
                        </td>
                        <td>{{ d.hostname or '-' }}</td>
                        <td>{{ d.username or '-' }}</td>
                        <td>{{ d.os_short }}</td>
                        <td><span class="font-mono tabular-nums">{{ d.ip or '-' }}</span></td>
                        <td>
                            {% if d.password %}
                            <span class="font-mono text-sm text-base-content/70">••••••••</span>
                            {% else %}
                            <span class="badge badge-warning text-xs font-semibold">Not Set</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if d.online %}
                            <span class="badge badge-success gap-1 text-xs font-semibold">
                                <span class="w-1.5 h-1.5 rounded-full bg-success-content motion-safe:animate-pulse"></span>
                                Online
                            </span>
                            {% elif not d.last_seen_iso %}
                            <span class="badge badge-outline text-xs font-semibold" title="This device has registered but never reported its status">Never seen</span>
                            {% else %}
                            <span class="badge badge-ghost text-xs font-semibold">Offline</span>
                            {% endif %}
                        </td>
                        <td data-order="{{ d.last_seen_iso }}"><span class="font-mono tabular-nums js-last-seen" data-ts="{{ d.last_seen_iso }}">-</span></td>
                        <td class="flex gap-1">
                            <button type="button" class="btn btn-primary btn-sm js-connect" data-id="{{ d.id }}" data-password="{{ d.password }}" title="Connect" aria-label="Connect to device {{ d.id }}">
                                <i data-lucide="link" class="w-4 h-4 mr-1" aria-hidden="true"></i>Connect
                            </button>
                            <button type="button" class="btn btn-outline btn-sm btn-square js-edit-password" data-id="{{ d.id }}" data-password="{{ d.password }}" title="Set Password" aria-label="Set password for device {{ d.id }}">
                                <i data-lucide="key" class="w-4 h-4" aria-hidden="true"></i>
                            </button>
                            <form action="/my-devices/unclaim/{{ d.id }}" method="POST" class="inline js-unclaim" data-hostname="{{ d.hostname or d.id }}">
                                <button type="submit" class="btn btn-ghost btn-sm btn-square text-error" title="Remove Device" aria-label="Unclaim device {{ d.id }}">
                                    <i data-lucide="trash-2" class="w-4 h-4" aria-hidden="true"></i>
                                </button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endif %}

<!-- Edit Password Modal -->
<dialog id="editPasswordModal" class="modal">
    <div class="modal-box">
        <form method="dialog">
            <button class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2" aria-label="Close modal">✕</button>
        </form>
        <h3 class="font-bold text-lg text-balance mb-4">Edit Connection Password</h3>
        <form action="{{ url_for('web_save_device_password') }}" method="POST" id="editPasswordForm">
            <input type="hidden" name="device_id" id="edit-device-id">
            <div class="form-control w-full mb-6">
                <label class="label" for="device-password-input"><span class="label-text font-semibold">Unattended Access Password</span></label>
                <div class="relative">
                    <input type="password" id="device-password-input" class="input input-bordered w-full pr-20" name="password" placeholder="Enter password…" autocomplete="new-password" spellcheck="false">
                    <div class="absolute right-3 top-3 flex gap-1">
                        <button type="button" class="btn btn-ghost btn-xs btn-square" id="btn-generate-password" title="Generate password" aria-label="Generate random password">
                            <i data-lucide="dices" class="w-5 h-5" aria-hidden="true"></i>
                        </button>
                        <button type="button" class="btn btn-ghost btn-xs btn-square" onclick="togglePasswordVisibility()" aria-label="Toggle password visibility">
                            <i data-lucide="eye" id="togglePasswordIcon" class="w-5 h-5" aria-hidden="true"></i>
                        </button>
                    </div>
                </div>
                <span class="label-text-alt text-base-content/70 mt-2 block">Set the permanent password configured on the remote client.</span>
            </div>
            <div class="flex justify-end gap-3 mt-4">
                <button type="button" class="btn btn-ghost" onclick="document.getElementById('editPasswordModal').close()">Cancel</button>
                <button type="submit" class="btn btn-primary" data-loading-text="Saving…">Save Password</button>
            </div>
        </form>
    </div>
    <form method="dialog" class="modal-backdrop">
        <button>close</button>
    </form>
</dialog>

{% endblock %}

{% block scripts %}
<script>
// tojson is the XSS-safe way to inject a server value into a JS context.
const ID_SERVER = {{ id_server | tojson }};

// NOTE: device data travels via data-* attributes (HTML-escaped by Jinja) and is
// read through dataset — never interpolated into inline JS strings. Inline
// handler interpolation was a stored-XSS vector (hostname is writable via the
// unauthenticated /api/sysinfo endpoint).

$(document).ready(function() {
    if ($.fn.DataTable && $('#myDevicesTable tbody tr').length) {
        window.initDataTable('#myDevicesTable', {
            order: [[7, 'desc']],
            pageLength: 25,
            language: {
                search: "Search:",
                lengthMenu: "Show _MENU_ devices"
            }
        });
    }
    renderLocalTimes();
});

function renderLocalTimes() {
    document.querySelectorAll('.js-last-seen').forEach(function(el) {
        const ts = el.dataset.ts;
        if (!ts) { el.textContent = '-'; return; }
        const date = new Date(ts);
        if (isNaN(date)) { el.textContent = '-'; return; }
        const diffMin = Math.floor((Date.now() - date.getTime()) / 60000);
        if (diffMin < 1) { el.textContent = 'just now'; return; }
        if (diffMin < 60) { el.textContent = diffMin + ' min ago'; return; }
        el.textContent = date.toLocaleString('en-GB', {day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'});
    });
}

function connectTo(id, password) {
    let url = 'rustdesk://' + encodeURIComponent(id);
    if (ID_SERVER) {
        url += '@' + encodeURIComponent(ID_SERVER);
    }
    if (password) {
        url += '?password=' + encodeURIComponent(password);
    }
    window.location.href = url;
}

document.addEventListener('click', function(e) {
    const connectBtn = e.target.closest('.js-connect');
    if (connectBtn) {
        connectTo(connectBtn.dataset.id, connectBtn.dataset.password || '');
        return;
    }
    const editBtn = e.target.closest('.js-edit-password');
    if (editBtn) {
        document.getElementById('edit-device-id').value = editBtn.dataset.id;
        document.getElementById('device-password-input').value = editBtn.dataset.password || '';
        document.getElementById('editPasswordModal').showModal();
        return;
    }
    const copyBtn = e.target.closest('.js-copy-id');
    if (copyBtn) {
        const id = copyBtn.dataset.id;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(id);
        } else {
            const tmp = document.createElement('textarea');
            tmp.value = id;
            document.body.appendChild(tmp);
            tmp.select();
            document.execCommand('copy');
            tmp.remove();
        }
        copyBtn.classList.add('text-success');
        setTimeout(function() { copyBtn.classList.remove('text-success'); }, 800);
    }
});

document.addEventListener('submit', function(e) {
    const form = e.target.closest('.js-unclaim');
    if (form && form.dataset.confirmed !== 'true') {
        e.preventDefault();
        e.stopPropagation();
        window.confirmDialog(
            'Remove device "' + (form.dataset.hostname || '') + '" from your account?',
            () => { form.dataset.confirmed = 'true'; form.requestSubmit(); },
            { confirmLabel: 'Remove' }
        );
    }
});

document.getElementById('btn-generate-password').addEventListener('click', function() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    const array = new Uint32Array(10);
    crypto.getRandomValues(array);
    let pwd = '';
    for (let i = 0; i < 10; i++) { pwd += chars[array[i] % chars.length]; }
    const input = document.getElementById('device-password-input');
    input.value = pwd;
    input.type = 'text';
    document.getElementById('togglePasswordIcon').setAttribute('data-lucide', 'eye-off');
    if (window.lucide) { lucide.createIcons(); }
});

function togglePasswordVisibility() {
    const input = document.getElementById('device-password-input');
    const icon = document.getElementById('togglePasswordIcon');
    if (input.type === 'password') {
        input.type = 'text';
        icon.setAttribute('data-lucide', 'eye-off');
    } else {
        input.type = 'password';
        icon.setAttribute('data-lucide', 'eye');
    }
    if (window.lucide) {
        lucide.createIcons();
    }
}
</script>
{% endblock %}
"""


# ==================== WEB ROUTES ====================

def render_page(template, **kwargs):
    kwargs['session'] = session
    kwargs['url_for'] = url_for
    kwargs['request'] = request
    kwargs['current_time'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    full_template = BASE_HTML.replace('{% block content %}{% endblock %}', template.split('{% block content %}')[1].split('{% endblock %}')[0])
    full_template = full_template.replace('{% block scripts %}{% endblock %}', template.split('{% block scripts %}')[1].split('{% endblock %}')[0] if '{% block scripts %}' in template else '')
    return render_template_string(full_template, **kwargs)

@app.route('/')
def web_index():
    if 'user_id' in session:
        return redirect(url_for('web_dashboard'))
    return redirect(url_for('web_login'))

@app.route('/login', methods=['GET', 'POST'])
def web_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"[LOGIN] Attempting login for user: {username}")
        
        user = None
        conn = get_db()
        
        # Check if LDAP is enabled - try LDAP FIRST for domain users
        ldap_enabled = is_ldap_enabled()
        print(f"[LOGIN] LDAP enabled: {ldap_enabled}")
        
        if ldap_enabled:
            print(f"[LOGIN] Trying LDAP authentication for: {username}")
            ldap_user = ldap_authenticate(username, password)
            
            if ldap_user:
                print(f"[LOGIN] LDAP auth SUCCESS for: {username}")
                # Sync LDAP user to local database
                # Check if user is member of any admin group
                user_groups = ldap_user.get('groups', [])
                admin_groups = get_ldap_admin_groups(conn)
                is_admin = any(group in user_groups for group in admin_groups)
                print(f"[LDAP] User '{ldap_user.get('username')}' groups: {user_groups}, is_admin: {is_admin}")
                user_id = sync_ldap_user_to_db(ldap_user, is_admin)
                
                if user_id:
                    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                    print(f"[LDAP] User '{username}' authenticated via LDAP, user_id: {user_id}")
            else:
                print(f"[LOGIN] LDAP auth FAILED for: {username}")
        
        # If LDAP failed or disabled, try local authentication.
        # Domain-managed rows (auth_source='ldap') have no usable local password.
        if not user:
            print(f"[LOGIN] Trying local authentication for: {username}")
            local_user = conn.execute("SELECT * FROM users WHERE username = ? AND COALESCE(auth_source, 'local') = 'local'",
                                      (username,)).fetchone()

            if local_user:
                print(f"[LOGIN] Found local user: {username}, checking password…")
                if verify_password(password, local_user['password']) and local_user['status'] == 1:
                    maybe_upgrade_password(conn, local_user, password)
                    user = local_user
                    print(f"[LOGIN] Local auth SUCCESS for: {username}")
                else:
                    print(f"[LOGIN] Local auth FAILED for: {username} (wrong password or disabled)")
            else:
                print(f"[LOGIN] Local user not found: {username}")
        
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            print(f"[LOGIN] Session created for: {username}, is_admin: {user['is_admin']}")
            return redirect(url_for('web_dashboard'))
        
        print(f"[LOGIN] Login FAILED for: {username}")
        error = 'Invalid username or password'
    
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/login-sso', methods=['GET'])
def web_login_sso():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Negotiate '):
        resp = make_response('', 401)
        resp.headers['WWW-Authenticate'] = 'Negotiate'
        return resp
    if not sso_kerberos.SPNEGO_AVAILABLE or not SSO_SPN:
        return redirect(url_for('web_login'))
    try:
        principal = sso_kerberos.validate_negotiate_token(auth_header.split(' ', 1)[1], SSO_SPN)
    except sso_kerberos.SsoError as e:
        print(f"[SSO] browser validation failed: {e}")
        return redirect(url_for('web_login'))
    u = resolve_sso_user(principal)
    if not u or not u['is_admin']:
        print(f"[SSO] browser login denied for principal: {principal}")
        return redirect(url_for('web_login'))
    session['user_id'] = u['user_id']
    session['username'] = u['username']
    session['is_admin'] = True
    return redirect(url_for('web_dashboard'))

@app.route('/logout')
def web_logout():
    session.clear()
    return redirect(url_for('web_login'))

def update_offline_devices(conn):
    # This function is kept for compatibility on writes (e.g. heartbeat updates)
    # but no longer called on read paths (GET requests) to prevent DB locks.
    conn.execute("UPDATE devices SET online = 0 WHERE datetime(last_seen) < datetime('now', '-30 seconds') OR last_seen IS NULL")

def get_devices_list(search_query=None, user_id=None):
    conn = get_db()
    if search_query:
        q = f"%{search_query}%"
        if user_id is not None:
            devices = conn.execute("SELECT * FROM devices WHERE user_id = ? AND (hostname LIKE ? OR username LIKE ? OR os LIKE ?) ORDER BY last_seen DESC", (user_id, q, q, q)).fetchall()
        else:
            devices = conn.execute("SELECT * FROM devices WHERE hostname LIKE ? OR username LIKE ? OR os LIKE ? ORDER BY last_seen DESC", (q, q, q)).fetchall()
    else:
        if user_id is not None:
            devices = conn.execute("SELECT * FROM devices WHERE user_id = ? ORDER BY last_seen DESC", (user_id,)).fetchall()
        else:
            devices = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()
    
    devices_list = []
    for d in devices:
        device = dict(d)
        
        # Calculate online status dynamically based on UTC timestamps
        is_online = 0
        last_seen = device.get('last_seen')
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen)
                if datetime.utcnow() - dt < timedelta(seconds=30):
                    is_online = 1
            except Exception:
                pass
        device['online'] = is_online
        
        # Short OS name
        os_full = device.get('os', '') or ''
        if 'Windows 11' in os_full:
            device['os_short'] = 'Windows 11'
        elif 'Windows 10' in os_full:
            device['os_short'] = 'Windows 10'
        elif 'Linux' in os_full:
            device['os_short'] = 'Linux'
        elif 'Mac' in os_full or 'Darwin' in os_full:
            device['os_short'] = 'macOS'
        else:
            device['os_short'] = os_full[:20] if os_full else '-'
        
        # Format last seen. last_seen_iso is the DataTables sort/filter key
        # (data-order attribute) since last_seen_str's DD.MM.YYYY display
        # format doesn't sort correctly as plain text across month/year
        # boundaries.
        if device['last_seen']:
            try:
                dt = datetime.fromisoformat(device['last_seen'])
                device['last_seen_str'] = dt.strftime('%d.%m.%Y %H:%M')
                device['last_seen_iso'] = dt.isoformat() + 'Z'
            except:
                device['last_seen_str'] = str(device['last_seen'])
                device['last_seen_iso'] = ''
        else:
            device['last_seen_str'] = 'Never'
            device['last_seen_iso'] = ''
        devices_list.append(device)
    return devices_list

def compute_dashboard_data(is_admin, user_id):
    """Compute KPI stats, 7-day connection series and OS distribution.

    Shared by the full-page dashboard render and the /api/dashboard/stats
    polling endpoint so the live refresh stays in lockstep with the SSR view.
    Returns a dict of plain Python values (JSON-serializable).
    """
    conn = get_db()
    if is_admin:
        total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE last_seen IS NOT NULL AND datetime(last_seen) >= datetime('now', '-30 seconds')"
        ).fetchone()[0]
        connections_today = conn.execute("SELECT COUNT(*) FROM connections WHERE date(started_at) = date('now')").fetchone()[0]
        users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    else:
        total = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id = ?", (user_id,)).fetchone()[0]
        online = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE user_id = ? AND last_seen IS NOT NULL AND datetime(last_seen) >= datetime('now', '-30 seconds')",
            (user_id,)
        ).fetchone()[0]
        connections_today = conn.execute(
            "SELECT COUNT(*) FROM connections WHERE device_id IN (SELECT id FROM devices WHERE user_id = ?) AND date(started_at) = date('now')",
            (user_id,)
        ).fetchone()[0]
        users_count = total  # For non-admins, show their total devices as secondary stat

    # Chart data - last 7 days
    chart_labels = []
    chart_data = []
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        label = (datetime.now() - timedelta(days=i)).strftime('%d.%m')
        if is_admin:
            count = conn.execute("SELECT COUNT(*) FROM connections WHERE date(started_at) = ?", (date,)).fetchone()[0]
        else:
            count = conn.execute(
                "SELECT COUNT(*) FROM connections WHERE device_id IN (SELECT id FROM devices WHERE user_id = ?) AND date(started_at) = ?",
                (user_id, date)
            ).fetchone()[0]
        chart_labels.append(label)
        chart_data.append(count)

    # OS distribution
    os_stats = {}
    if is_admin:
        devices = conn.execute("SELECT os FROM devices WHERE os IS NOT NULL AND os != ''").fetchall()
    else:
        devices = conn.execute("SELECT os FROM devices WHERE user_id = ? AND os IS NOT NULL AND os != ''", (user_id,)).fetchall()
    for d in devices:
        os_name = d['os'] or ''
        if 'Windows 11' in os_name:
            key = 'Windows 11'
        elif 'Windows 10' in os_name:
            key = 'Windows 10'
        elif 'Linux' in os_name:
            key = 'Linux'
        elif 'Mac' in os_name or 'Darwin' in os_name:
            key = 'macOS'
        else:
            key = 'Other'
        os_stats[key] = os_stats.get(key, 0) + 1

    conn.close()
    return {
        'stats': {
            'total': total,
            'online': online,
            'connections_today': connections_today,
            'users': users_count,
        },
        'chart_labels': chart_labels,
        'chart_data': chart_data,
        'os_labels': list(os_stats.keys()),
        'os_data': list(os_stats.values()),
    }

@app.route('/api/dashboard/stats')
@web_login_required
def api_dashboard_stats():
    """Live dashboard data for in-place polling (no full-page reload)."""
    data = compute_dashboard_data(session.get('is_admin'), session.get('user_id'))
    data['device_online'] = {
        d['id']: bool(d['online'])
        for d in get_devices_list(user_id=None if session.get('is_admin') else session.get('user_id'))
    }
    return jsonify(data)

@app.route('/dashboard')
@web_login_required
def web_dashboard():
    is_admin = session.get('is_admin')
    user_id = session.get('user_id')
    data = compute_dashboard_data(is_admin, user_id)
    total = data['stats']['total']
    online = data['stats']['online']
    connections_today = data['stats']['connections_today']
    users_count = data['stats']['users']
    chart_labels = data['chart_labels']
    chart_data = data['chart_data']
    os_stats_keys = data['os_labels']
    os_stats_values = data['os_data']
    
    devices_list = get_devices_list(user_id=None if is_admin else user_id)
    
    return render_page(DASHBOARD_HTML,
        title='Dashboard',
        active_page='dashboard',
        stats={
            'total': total,
            'online': online,
            'connections_today': connections_today,
            'users': users_count
        },
        devices=devices_list,
        # Raw Python lists — the template renders them with |tojson for the
        # Chart.js <script> block AND uses them directly in {% if %}/{% for %}
        # for the accessible data-table fallback and empty-state check.
        chart_labels=chart_labels,
        chart_data=chart_data,
        os_labels=os_stats_keys,
        os_data=os_stats_values
    )

@app.route('/devices')
@admin_required
def web_devices():
    search_query = request.args.get('search', '')
    devices_list = get_devices_list(search_query)
    return render_page(DEVICES_HTML,
        title='Devices',
        active_page='devices',
        devices=devices_list,
        search_query=search_query
    )

@app.route('/users')
@admin_required
def web_users():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    
    return render_page(USERS_HTML,
        title='Users',
        active_page='users',
        users=users
    )

@app.route('/users/add', methods=['POST'])
@admin_required
def web_add_user():
    username = request.form.get('username')
    email = request.form.get('email', '')
    password = request.form.get('password')
    is_admin = 1 if request.form.get('is_admin') else 0
    
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                     (username, hash_password(password), email, is_admin))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    
    return redirect(url_for('web_users'))

@app.route('/logs')
@admin_required
def web_logs():
    log_type = request.args.get('type', 'all')
    
    conn = get_db()
    if log_type == 'all':
        logs = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500").fetchall()
    else:
        logs = conn.execute("SELECT * FROM audit_logs WHERE type = ? ORDER BY created_at DESC LIMIT 500", (log_type,)).fetchall()
    conn.close()
    
    return render_page(LOGS_HTML,
        title='Logs',
        active_page='logs',
        logs=logs,
        log_type=log_type
    )

@app.route('/settings')
@admin_required
def web_settings():
    conn = get_db()
    settings = {}
    for row in conn.execute("SELECT key, value FROM settings").fetchall():
        settings[row['key']] = row['value']
    conn.close()
    
    ldap_config = {
        'server': settings.get('ldap_server', ''),
        'base_dn': settings.get('ldap_base_dn', ''),
        'bind_dn': settings.get('ldap_bind_dn', ''),
        'admin_groups': settings.get('ldap_admin_groups', 'Domain Admins, Administrators, Enterprise Admins, Администраторы домена, Администраторы, Admins, IT Admins, RustDesk Admins'),
        'enabled': settings.get('ldap_enabled', '') == '1'
    }
    
    global_settings_raw = settings.get('global_settings', '{}')
    try:
        global_settings = json.loads(global_settings_raw)
    except Exception:
        global_settings = {}
    
    id_server = get_id_server()
    return render_page(SETTINGS_HTML,
        title='Settings',
        active_page='settings',
        ldap_config=ldap_config,
        ldap_available=LDAP_AVAILABLE,
        global_settings=global_settings,
        id_server=id_server,
        relay_server=id_server
    )

@app.route('/settings/ldap', methods=['POST'])
@admin_required
def web_save_ldap():
    conn = get_db()
    settings = {
        'ldap_server': request.form.get('ldap_server', '').strip(),
        'ldap_base_dn': request.form.get('ldap_base_dn', '').strip(),
        'ldap_bind_dn': request.form.get('ldap_bind_dn', '').strip(),
        'ldap_admin_groups': request.form.get('ldap_admin_groups', '').strip(),
        'ldap_enabled': '1' if request.form.get('ldap_enabled') else '0'
    }
    
    password = request.form.get('ldap_bind_password', '')
    if password:
        settings['ldap_bind_password'] = password
    
    for key, value in settings.items():
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

    conn.commit()
    conn.close()

    return redirect(url_for('web_settings', saved='ldap'))

@app.route('/settings/global', methods=['POST'])
@admin_required
def web_save_global():
    conn = get_db()
    
    global_settings = {
        'theme': request.form.get('theme', ''),
        'enable-lan-discovery': request.form.get('enable-lan-discovery', ''),
        'approve-mode': request.form.get('approve-mode', ''),
        'verification-method': request.form.get('verification-method', ''),
        'allow-remote-config-modification': request.form.get('allow-remote-config-modification', ''),
        'allow-numeric-one-time-password': request.form.get('allow-numeric-one-time-password', ''),
        'enable-keyboard': request.form.get('enable-keyboard', ''),
        'enable-clipboard': request.form.get('enable-clipboard', ''),
        'enable-file-transfer': request.form.get('enable-file-transfer', ''),
        'enable-audio': request.form.get('enable-audio', '')
    }
    
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                 ('global_settings', json.dumps(global_settings)))
    conn.commit()
    conn.close()

    return redirect(url_for('web_settings', saved='global'))

@app.route('/api/global-settings', methods=['GET'])
def api_global_settings():
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = 'global_settings'").fetchone()
    conn.close()
    
    options = {}
    if row:
        try:
            raw_options = json.loads(row['value'])
            options = {k: v for k, v in raw_options.items() if v != ''}
        except Exception:
            pass
            
    return jsonify({
        'options': options
    })

# ==================== CLIENT VERSION CHECK (auto-update) ====================
# The RustDesk client (hbb_common::version_check_request) POSTs here when the
# 'api-server' option is set. Answer with the newest semver-tagged GitHub
# release that actually ships the flutter installer for the client's arch;
# the client then derives the download URL (…/tag/X.Y.Z -> …/download/X.Y.Z/…).

GITHUB_RELEASES_REPO = os.environ.get('UPDATE_GITHUB_REPO', 'klarnet2009/rustdesk')
_VERSION_CACHE_TTL = 300  # seconds; keeps us clear of GitHub's 60 req/h unauth limit
_version_cache = {}       # arch -> (timestamp, url)

def _parse_semver(tag):
    m = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)', tag or '')
    return tuple(int(g) for g in m.groups()) if m else None

def _latest_release_url_for_arch(arch):
    now = time.time()
    cached = _version_cache.get(arch)
    if cached and now - cached[0] < _VERSION_CACHE_TTL:
        return cached[1]
    url = ''
    try:
        req = urllib.request.Request(
            f'https://api.github.com/repos/{GITHUB_RELEASES_REPO}/releases',
            headers={'User-Agent': 'rustdesk-web-panel', 'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            releases = json.loads(resp.read())
        best = None
        for rel in releases:
            if rel.get('draft'):
                continue
            tag = rel.get('tag_name', '')
            ver = _parse_semver(tag)
            if not ver:
                continue  # 'nightly'/'beta' tags are not version-comparable
            names = {a.get('name', '') for a in rel.get('assets', [])}
            if f'rustdesk-{tag}-{arch}.msi' not in names and f'rustdesk-{tag}-{arch}.exe' not in names:
                continue  # release without a flutter installer for this arch
            if best is None or ver > best[0]:
                best = (ver, tag)
        if best:
            url = f'https://github.com/{GITHUB_RELEASES_REPO}/releases/tag/{best[1]}'
    except Exception as e:
        print(f"[VERSION] GitHub release check failed: {e}")
    _version_cache[arch] = (now, url)
    return url

@app.route('/api/version/latest', methods=['POST'])
def api_version_latest():
    data = request.get_json(silent=True) or {}
    arch = data.get('arch') or 'x86_64'
    if arch == 'x86':
        arch = 'x86_64'  # this fork does not publish 32-bit installers
    return jsonify({'url': _latest_release_url_for_arch(arch)})

@app.route('/api/ldap/test', methods=['POST'])
@web_login_required
def api_ldap_test():
    """Test LDAP connection and discover Base DN dynamically"""
    data = request.json or {}
    server = data.get('server')
    user = data.get('username')
    pw = data.get('password')
    
    success, message, base_dn = test_ldap_connection(server, user, pw)
    return jsonify({
        "success": success,
        "message": message,
        "base_dn": base_dn,
        "ldap_available": LDAP_AVAILABLE
    })

# ==================== API ROUTES ====================

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@app.route('/api/login-sso', methods=['GET', 'POST', 'OPTIONS'])
def api_login_sso():
    if request.method == 'OPTIONS':
        return '', 200
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Negotiate '):
        resp = make_response(jsonify({'error': 'Negotiate authentication required'}), 401)
        resp.headers['WWW-Authenticate'] = 'Negotiate'
        return resp
    if not sso_kerberos.SPNEGO_AVAILABLE:
        return jsonify({'error': 'Kerberos SSO not available on this server'}), 501
    if not SSO_SPN:
        return jsonify({'error': 'SSO_SPN not configured on this server'}), 501
    token_b64 = auth_header.split(' ', 1)[1]
    try:
        principal = sso_kerberos.validate_negotiate_token(token_b64, SSO_SPN)
    except sso_kerberos.SsoError as e:
        print(f"[SSO] validation failed: {e}")
        resp = make_response(jsonify({'error': 'Kerberos validation failed'}), 401)
        resp.headers['WWW-Authenticate'] = 'Negotiate'
        return resp
    u = resolve_sso_user(principal)
    if not u:
        return jsonify({'error': 'SSO principal collides with a local account'}), 403
    access_token = create_token(u['user_id'], u['username'], u['is_admin'])
    print(f"[SSO] client login OK: {u['username']} (admin={u['is_admin']})")
    return jsonify({
        'access_token': access_token,
        'type': 'access_token',
        'user': {
            'name': u['username'],
            'email': u['email'],
            'is_admin': u['is_admin'],
            'status': 'active',
        },
    })

@app.route('/api/login-options', methods=['GET', 'OPTIONS'])
def api_login_options():
    return jsonify({"oidc": [], "2fa": False})

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def api_login():
    if request.method == 'OPTIONS':
        return '', 200
    
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    device_id = data.get('id', '')
    
    user = None
    conn = get_db()
    
    # Try LDAP first if enabled
    if is_ldap_enabled():
        ldap_user = ldap_authenticate(username, password)
        if ldap_user:
            user_groups = ldap_user.get('groups', [])
            admin_groups = get_ldap_admin_groups(conn)
            is_admin = any(group in user_groups for group in admin_groups)
            user_id = sync_ldap_user_to_db(ldap_user, is_admin)
            if user_id:
                user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                
    # Fallback to local authentication (local rows only — domain-managed rows
    # have no usable local password)
    if not user:
        local_user = conn.execute("SELECT * FROM users WHERE username = ? AND COALESCE(auth_source, 'local') = 'local'",
                                  (username,)).fetchone()
        if local_user and verify_password(password, local_user['password']):
            maybe_upgrade_password(conn, local_user, password)
            user = local_user
            
    if not user:
        conn.close()
        return jsonify({"error": "Invalid credentials"})
        
    if user['status'] != 1:
        conn.close()
        return jsonify({"error": "User disabled"})
    
    if device_id:
        uuid = data.get('uuid', '')
        assign_device_to_user(conn, device_id, uuid, user['id'], user['username'])
    
    conn.close()
    
    token = create_token(user['id'], user['username'], user['is_admin'])
    
    return jsonify({
        "access_token": token,
        "type": "access_token",
        "user": {
            "name": user['username'],
            "display_name": user['display_name'] or '',
            "email": user['email'],
            "status": user['status'],
            "is_admin": bool(user['is_admin']),
            "info": {}
        }
    })

@app.route('/api/resolve', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def api_resolve():
    """Resolve a PC hostname to its RustDesk ID (connect-by-name support)."""
    if request.method == 'OPTIONS':
        return '', 200
    name = request.args.get('name', '')
    if not name and request.is_json:
        try:
            name = (request.get_json(silent=True) or {}).get('name', '')
        except Exception:
            name = ''
    name = name.strip()
    if not name:
        return jsonify({'error': 'name required'}), 400

    conn = get_db()
    try:
        # Exact hostname match (case-insensitive), most recently seen first
        d = conn.execute(
            "SELECT id, hostname FROM devices WHERE LOWER(hostname) = LOWER(?) ORDER BY last_seen DESC LIMIT 1",
            (name,)).fetchone()
        if not d:
            # Prefix match (type-ahead style)
            d = conn.execute(
                "SELECT id, hostname FROM devices WHERE hostname LIKE ? ORDER BY last_seen DESC LIMIT 1",
                (name + '%',)).fetchone()
    finally:
        conn.close()

    if not d:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'id': d['id'], 'hostname': d['hostname']})

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@token_required
def api_logout():
    return jsonify({"success": True})

@app.route('/api/currentUser', methods=['POST', 'OPTIONS'])
@token_required
def api_current_user():
    if request.method == 'OPTIONS':
        return '', 200
        
    # Read device id and uuid from request JSON if available
    data = {}
    if request.is_json:
        try:
            data = request.json or {}
        except Exception:
            pass
            
    device_id = data.get('id', '')
    uuid = data.get('uuid', '')
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (request.current_user['user_id'],)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({"error": "User not found"})
        
    if device_id:
        assign_device_to_user(conn, device_id, uuid, user['id'], user['username'])
        
    conn.close()
    
    return jsonify({
        "name": user['username'],
        "display_name": user['display_name'] or '',
        "email": user['email'],
        "status": user['status'],
        "is_admin": bool(user['is_admin']),
    })

def merge_address_book(user_id, ab_data_str):
    import json
    try:
        ab = json.loads(ab_data_str) if ab_data_str else {"tags": [], "peers": []}
    except Exception:
        ab = {"tags": [], "peers": []}
        
    if "peers" not in ab:
        ab["peers"] = []
    if "tags" not in ab:
        ab["tags"] = []
        
    conn = get_db()
    devices = conn.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    
    for d in devices:
        device_id = d['id']
        is_online = 0
        last_seen = d['last_seen']
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen)
                if datetime.utcnow() - dt < timedelta(seconds=30):
                    is_online = 1
            except Exception:
                pass
                
        peer_found = False
        for p in ab['peers']:
            if p.get('id') == device_id:
                peer_found = True
                p['password'] = d['password'] or p.get('password') or ''
                p['username'] = d['username'] or p.get('username') or 'admin'
                p['hostname'] = d['hostname'] or p.get('hostname') or device_id
                p['online'] = bool(is_online)
                if 'tags' not in p or not isinstance(p['tags'], list):
                    p['tags'] = []
                if 'same-account' not in p['tags']:
                    p['tags'].append('same-account')
                break
                
        if not peer_found:
            ab['peers'].append({
                "id": device_id,
                "username": d['username'] or 'admin',
                "hostname": d['hostname'] or device_id,
                "platform": (d['os'] or 'windows').lower().split(' ')[0],
                "password": d['password'] or '',
                "alias": d['hostname'] or device_id,
                "tags": ['same-account'],
                "online": bool(is_online)
            })
            
    return json.dumps(ab)

def sync_passwords_from_ab(user_id, ab_data_str):
    import json
    try:
        ab = json.loads(ab_data_str)
        peers = ab.get('peers', [])
    except Exception:
        return
        
    if not peers:
        return
        
    conn = get_db()
    for p in peers:
        peer_id = p.get('id')
        password = p.get('password')
        if peer_id and password:
            conn.execute("UPDATE devices SET password = ? WHERE id = ? AND user_id = ?", (password, peer_id, user_id))
    conn.commit()
    conn.close()

@app.route('/api/ab/get', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def api_get_ab():
    user_id = request.current_user['user_id']
    conn = get_db()
    ab = conn.execute("SELECT * FROM address_books WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    
    raw_data = ab['data'] if ab else '{"tags":[],"peers":[]}'
    merged_data = merge_address_book(user_id, raw_data)
    return jsonify({"updated_at": int(time.time()), "data": merged_data})

@app.route('/api/ab', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def api_ab():
    """Address Book - GET to retrieve, POST to update"""
    user_id = request.current_user['user_id']
    conn = get_db()
    
    if request.method == 'GET':
        ab = conn.execute("SELECT * FROM address_books WHERE user_id = ?", 
                          (user_id,)).fetchone()
        conn.close()
        raw_data = ab['data'] if ab else '{"tags":[],"peers":[]}'
        merged_data = merge_address_book(user_id, raw_data)
        return jsonify({"updated_at": int(time.time()), "data": merged_data})
    
    else:
        data = request.json or {}
        ab_data = data.get('data', '')
        
        # Save address book for specific user
        conn.execute("INSERT OR REPLACE INTO address_books (user_id, data, updated_at) VALUES (?, ?, datetime('now'))",
                     (user_id, ab_data))
        conn.commit()
        conn.close()
        
        # Sync passwords back to the devices table
        sync_passwords_from_ab(user_id, ab_data)
        
        return jsonify({"success": True})

@app.route('/api/heartbeat', methods=['POST', 'OPTIONS'])
def api_heartbeat():
    if request.method == 'OPTIONS':
        return '', 200
    
    data = request.json or {}
    device_id = sanitize_field(data.get('id', ''), 64)
    uuid = sanitize_field(data.get('uuid', ''), 64)
    
    if device_id:
        conn = get_db()
        conn.execute('''INSERT INTO devices (id, uuid, online, last_seen) VALUES (?, ?, 1, datetime('now'))
                        ON CONFLICT(id) DO UPDATE SET uuid = excluded.uuid, online = 1, last_seen = datetime('now')''',
                     (device_id, uuid))
        update_offline_devices(conn)
        conn.commit()
        conn.close()
    
    return jsonify({"modified_at": int(time.time())})

@app.route('/api/sysinfo', methods=['POST', 'OPTIONS'])
def api_sysinfo():
    if request.method == 'OPTIONS':
        return '', 200
    
    data = request.json or {}
    device_id = data.get('id', '')
    
    if not device_id:
        return 'ID_NOT_FOUND', 200
    
    client_ip = sanitize_field(data.get('ip', ''), 45) or request.remote_addr
    
    conn = get_db()
    conn.execute('''INSERT INTO devices (id, uuid, hostname, os, username, version, cpu, memory, ip, online, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'))
                    ON CONFLICT(id) DO UPDATE SET
                    uuid = excluded.uuid, hostname = excluded.hostname, os = excluded.os,
                    username = excluded.username, version = excluded.version, cpu = excluded.cpu,
                    memory = excluded.memory, ip = excluded.ip, online = 1, last_seen = datetime('now')''',
                 (sanitize_field(device_id, 64), sanitize_field(data.get('uuid', ''), 64),
                  sanitize_field(data.get('hostname', ''), 128), sanitize_field(data.get('os', ''), 64),
                  sanitize_field(data.get('username', ''), 64), sanitize_field(data.get('version', ''), 32),
                  sanitize_field(data.get('cpu', ''), 128), sanitize_field(data.get('memory', ''), 32),
                  client_ip))
    conn.commit()
    conn.close()
    
    print(f"[SYSINFO] {device_id} | {data.get('hostname', '')} | {data.get('username', '')} | {client_ip}")
    return 'SYSINFO_UPDATED', 200

@app.route('/api/sysinfo_ver', methods=['POST'])
def api_sysinfo_ver():
    return '1', 200

@app.route('/api/audit/<typ>', methods=['POST', 'OPTIONS'])
def api_audit(typ):
    if request.method == 'OPTIONS':
        return '', 200
    
    data = request.json or {}
    
    conn = get_db()
    conn.execute("INSERT INTO audit_logs (type, device_id, peer_id, action, data) VALUES (?, ?, ?, ?, ?)",
                 (typ, data.get('id', ''), data.get('peer_id', ''), data.get('action', ''), json.dumps(data)))
    
    if typ == 'conn':
        conn.execute("INSERT INTO connections (device_id, peer_id, conn_type) VALUES (?, ?, ?)",
                     (data.get('id', ''), data.get('peer_id', ''), data.get('type', '')))
    
    conn.commit()
    conn.close()
    
    print(f"[AUDIT:{typ}] {data}")
    return jsonify({"success": True})

@app.route('/api/admin/devices', methods=['GET'])
@token_required
def api_admin_devices():
    if not request.current_user.get('is_admin'):
        return jsonify({"error": "Access denied"}), 403
    
    search_query = request.args.get('search', '')
    conn = get_db()
    if search_query:
        q = f"%{search_query}%"
        devices = conn.execute("SELECT * FROM devices WHERE hostname LIKE ? OR username LIKE ? OR os LIKE ? ORDER BY last_seen DESC", (q, q, q)).fetchall()
    else:
        devices = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()
    
    devices_list = []
    for d in devices:
        device = dict(d)
        is_online = 0
        last_seen = device.get('last_seen')
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen)
                if datetime.utcnow() - dt < timedelta(seconds=30):
                    is_online = 1
            except Exception:
                pass
        device['online'] = is_online
        devices_list.append(device)
    
    return jsonify({"devices": devices_list})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@token_required
def api_delete_user(user_id):
    if not request.current_user.get('is_admin'):
        return jsonify({"error": "Access denied"}), 403
    
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ? AND username != 'admin'", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route('/api/stats/connections', methods=['GET'])
def api_stats_connections():
    conn = get_db()
    data = []
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        count = conn.execute("SELECT COUNT(*) FROM connections WHERE date(started_at) = ?", (date,)).fetchone()[0]
        data.append({"date": date, "count": count})
    conn.close()
    return jsonify(data)

@app.route('/api/peers', methods=['GET', 'OPTIONS'])
@token_required
def api_peers():
    if request.method == 'OPTIONS':
        return '', 200
        
    conn = get_db()
    # Fetch devices belonging to the user
    devices = conn.execute("SELECT * FROM devices WHERE user_id = ?", (request.current_user['user_id'],)).fetchall()
    conn.close()
    
    peers_list = []
    for d in devices:
        is_online = 0
        last_seen = d['last_seen']
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen)
                if datetime.utcnow() - dt < timedelta(seconds=30):
                    is_online = 1
            except Exception:
                pass
        
        peer = {
            "id": d['id'],
            "user": str(d['user_id']),
            "user_name": d['username'] or '',
            "device_group_name": d['group_name'] or 'Default',
            "note": "",
            "status": is_online,
            "info": {
                "os": d['os'] or '',
                "username": d['username'] or '',
                "device_name": d['hostname'] or ''
            }
        }
        peers_list.append(peer)
        
    return jsonify({"data": peers_list})

# ==================== MAIN ====================

# Initialize DB on module load (for Gunicorn)
init_db()


def get_id_server():
    # ID/relay host clients should use = the host the panel is served on
    # (Traefik forwards the real Host header). A stored setting overrides, unless
    # it's the retired 10.21.31.11 address. Falls back to the known domain.
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = 'id_server'").fetchone()
    conn.close()
    stored = row['value'] if row and row['value'] else ''
    if stored and stored != '10.21.31.11':
        return stored
    try:
        host = (request.host or '').split(':')[0]
    except Exception:
        host = ''
    return host or 'rustdesk.iterum.lv'

@app.route('/my-devices')
@web_login_required
def web_my_devices():
    conn = get_db()
    devices = conn.execute("SELECT * FROM devices WHERE user_id = ? ORDER BY last_seen DESC", (session['user_id'],)).fetchall()
    conn.close()
    
    id_server = get_id_server()
    
    devices_list = []
    for d in devices:
        is_online = 0
        last_seen = d['last_seen']
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen)
                if datetime.utcnow() - dt < timedelta(seconds=30):
                    is_online = 1
            except Exception:
                pass
                
        last_seen_iso = ''
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen)
                # Stored as UTC ("datetime('now')"); mark it so the browser can
                # convert to the viewer's local timezone.
                last_seen_iso = dt.isoformat() + 'Z'
            except Exception:
                pass
                
        # Short OS name
        os_full = d['os'] or ''
        if 'Windows 11' in os_full:
            os_short = 'Windows 11'
        elif 'Windows 10' in os_full:
            os_short = 'Windows 10'
        elif 'Linux' in os_full:
            os_short = 'Linux'
        elif 'Mac' in os_full or 'Darwin' in os_full:
            os_short = 'macOS'
        else:
            os_short = os_full[:20] if os_full else '-'
                
        devices_list.append({
            'id': d['id'],
            'hostname': d['hostname'],
            'username': d['username'],
            'os': d['os'],
            'os_short': os_short,
            'ip': d['ip'],
            'version': d['version'],
            'cpu': d['cpu'],
            'memory': d['memory'],
            'online': is_online,
            'password': d['password'] or '',
            'last_seen_iso': last_seen_iso
        })
        
    return render_page(MY_DEVICES_HTML,
        title='My Devices',
        active_page='my_devices',
        devices=devices_list,
        id_server=id_server
    )

@app.route('/my-devices/save-password', methods=['POST'])
@web_login_required
def web_save_device_password():
    device_id = request.form.get('device_id')
    password = request.form.get('password', '')
    
    if not device_id:
        return redirect(url_for('web_my_devices'))
        
    conn = get_db()
    # Security check: verify ownership
    device = conn.execute("SELECT * FROM devices WHERE id = ? AND user_id = ?", (device_id, session['user_id'])).fetchone()
    if device:
        conn.execute("UPDATE devices SET password = ? WHERE id = ?", (password, device_id))
        conn.commit()
        print(f"[MY DEVICES] Updated password for device: {device_id} (owned by user {session['username']})")
    conn.close()
    
    return redirect(url_for('web_my_devices'))

# NOTE: the manual /my-devices/claim route was removed: it allowed any logged-in
# user to hijack ANY device by ID without proof of ownership. Devices are linked
# automatically on client login (assign_device_to_user) — that is the only path.

@app.route('/my-devices/unclaim/<device_id>', methods=['POST'])
@web_login_required
def web_unclaim_device(device_id):
    conn = get_db()
    device = conn.execute("SELECT * FROM devices WHERE id = ? AND user_id = ?", (device_id, session['user_id'])).fetchone()
    if device:
        conn.execute("UPDATE devices SET user_id = NULL, password = NULL WHERE id = ?", (device_id,))
        conn.commit()
        print(f"[MY DEVICES] Unclaimed device: {device_id} for user {session['username']}")
    conn.close()
    return redirect(url_for('web_my_devices'))

if __name__ == '__main__':
    
    # Force HTTP mode for Coolify's reverse proxy terminating SSL
    ssl_context = None
    protocol = "http"
    ssl_status = "MANAGED BY REVERSE PROXY (Coolify)"
    
    # Warn loudly if the default admin credentials are still active
    try:
        _conn = get_db()
        _admin = _conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        _conn.close()
        if _admin and verify_password('admin123', _admin['password']):
            print("[SECURITY] WARNING: default admin/admin123 credentials are ACTIVE — change the admin password immediately!")
    except Exception:
        pass
    
    print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║          RustDesk Web Management Panel v2.0 (Tailwind)            ║
╠═══════════════════════════════════════════════════════════════════╣
║  Web Panel:  {protocol}://{HOST}:{PORT}                                ║
║  API:        {protocol}://{HOST}:{PORT}/api/                           ║
║  SSL:        {ssl_status}                                  ║
╠═══════════════════════════════════════════════════════════════════╣
║  NOTE: Run 'npm run build' first to compile Tailwind CSS!         ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    # debug=True enables Werkzeug's auto-reloader, which restarts the server
    # whenever the app writes files (SQLite DB, logs, LDAP sync) — killing
    # in-flight requests and producing intermittent 502s behind the reverse
    # proxy right after login. Run without debug/reloader; keep threaded=True
    # so concurrent dashboard/API requests are served.
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False, ssl_context=ssl_context)
