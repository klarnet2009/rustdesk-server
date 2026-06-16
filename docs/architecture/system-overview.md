# System Overview

## Purpose of the System
RustDesk is a full-featured, open-source remote control alternative to TeamViewer or AnyDesk. The system consists of the remote desktop client, ID/Relay server infrastructure (`hbbs` / `hbbr`), and a central Web Management Panel for administrative control.

## High-Level Architecture
The system consists of three main subsystems:
1. **RustDesk Client**: The desktop/mobile application used to connect to peers or receive remote support.
2. **RustDesk Server Components**:
   - **hbbs (ID Server)**: Authenticates clients, handles connection requests, and acts as the initial coordinate broker.
   - **hbbr (Relay Server)**: Relays remote connection traffic when a direct peer-to-peer (P2P) connection cannot be established.
3. **Web Management Panel**: A web-based console allowing administrators to monitor active sessions, manage devices, manage system users, and configure Active Directory/LDAP integration.

## Major Responsibilities of Each Subsystem
* **hbbs**: Listens for incoming client registrations, keeps track of online status, registers IDs, and generates session coordination keys.
* **hbbr**: Routes connection traffic between controller and target client when direct routing is unavailable.
* **Web Panel**: Exposes HTTP/REST APIs and Jinga/HTML views to view audit logs, manage devices, query connection histories, configure system-wide parameters, and manage security settings.

## Technology Stack
* **Core Servers (hbbs/hbbr)**: Written in Rust for maximum speed, security, and safety.
* **Web Management Panel**:
  - **Backend**: Python 3 and Flask. SQLite database for user/device metadata persistence. PyJWT for auth token validation.
  - **Frontend**: DaisyUI v4, Tailwind CSS v3, and HTML5. Icons provided by Lucide. Dynamic charts powered by Chart.js. jQuery DataTables for paginated lists.

## Architectural Philosophy
Our architectural philosophy prioritizes simplicity, clean boundaries, and zero-compromise design:
* **Consolidation**: Eliminating duplication by having a single, unified web panel hosted exclusively on the server side (`rustdesk-server/web_panel`), removing all client-side duplicates.
* **Visual Excellence**: Employing DaisyUI themes and Vercel Web Interface Guidelines for professional, accessible, and high-performance user interfaces.
* **Security & Transparency**: Structured logging, proper database path isolation, and clean authentication layers.
