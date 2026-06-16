# Codebase Navigation Guide

## Directory Layout

```
D:/rustdesk_src/
  ├── docs/                        # Architecture & system documentation
  ├── rustdesk-server/             # RustDesk server component codebase
  │   ├── libs/                    # Shared libraries
  │   ├── src/                     # Rust source code (hbbs/hbbr)
  │   └── web_panel/               # Server-side Web Management Panel
  └── rustdesk/                    # RustDesk client codebase
      ├── src/                     # Rust source code
      │   ├── common.rs            # Core client utilities and update check triggers
      │   ├── updater.rs           # Windows background updater service
      │   └── flutter_ffi.rs       # Rust-Flutter FFI bindings (update-me key handler, Windows SSPI SSO collector)
      └── flutter/                 # Flutter UI application codebase
          ├── lib/
          │   ├── main.dart        # Client entry point (launches update check)
          │   ├── common.dart      # Common client state, handles update events
          │   ├── widgets/
          │   │   └── update_dialog.dart # Mobile Update Dialog & Controller
          │   └── desktop/
          │       └── widgets/
          │           └── update_progress.dart # Desktop Update progress widget
          └── android/             # Android Kotlin source files
              └── app/src/.../UpdateService.kt # Kotlin APK downloader and installer
```

## Major Entry Points
* **hbbs/hbbr**: Starting binary compilations from `rustdesk-server/Cargo.toml`.
* **Web Panel**: `rustdesk-server/web_panel/server.py` is the execution target for Flask.

## Configuration Files
* **Tailwind**: `tailwind.config.js` defines templates paths and configures the default DaisyUI theme settings (`corporate` light / `business` dark mode).
* **Flask Config**: `server.py` reads global parameters (`HOST`, `PORT`, `DB_PATH`, `JWT_SECRET`) from environmental variables, falling back to secure defaults.
