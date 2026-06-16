# Codebase Navigation Guide

## Directory Layout

```
D:/rustdesk_src/
  ├── docs/                        # Architecture & system documentation
  ├── rustdesk-server/             # RustDesk server component codebase
  │   ├── libs/                    # Shared libraries
  │   ├── src/                     # Rust source code (hbbs/hbbr)
  │   └── web_panel/               # Server-side Web Management Panel
  │       ├── src/
  │       │   └── input.css        # Source Tailwind CSS & custom selectors
  │       ├── static/
  │       │   └── output.css       # Production Tailwind CSS compiled assets
  │       ├── ldap_auth.py         # AD / LDAP authentication logic
  │       ├── package.json         # Tailwind/DaisyUI devDependencies
  │       ├── server.py            # Flask server, route controllers & HTML templates
  │       └── tailwind.config.js   # Tailwind & DaisyUI configuration
```

## Major Entry Points
* **hbbs/hbbr**: Starting binary compilations from `rustdesk-server/Cargo.toml`.
* **Web Panel**: `rustdesk-server/web_panel/server.py` is the execution target for Flask.

## Configuration Files
* **Tailwind**: `tailwind.config.js` defines templates paths and configures the default DaisyUI theme settings (`corporate` light / `business` dark mode).
* **Flask Config**: `server.py` reads global parameters (`HOST`, `PORT`, `DB_PATH`, `JWT_SECRET`) from environmental variables, falling back to secure defaults.
