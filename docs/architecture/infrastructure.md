# Infrastructure Documentation

## 1. Hosting Environment
The RustDesk server infrastructure can be run as standalone binaries, systemd services, or containerized applications. It integrates natively with host managers like **Coolify** or Docker environments.

## 2. Docker Setup
The Web Management Panel includes a `Dockerfile` for self-contained, isolated deployments.

```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN apt-get update && apt-get install -y nodejs npm && npm install && npm run build
EXPOSE 21114
CMD ["python", "server.py"]
```

## 3. Database
* **Engine**: SQLite.
* **Storage Path**: Resolved absolutely to prevent database splitting or duplicates. Defaults to `/var/lib/rustdesk/rustdesk.db` or the parent directory of `server.py` (`rustdesk-server/rustdesk.db` or similar).

## 4. Port Allocations
* `21114`: Web Management Panel HTTP.
* `21115`: ID Server (hbbs) TCP signaling.
* `21116`: ID Server (hbbs) TCP/UDP registration.
* `21117`: Relay Server (hbbr) TCP traffic.
* `21118`: ID Server (hbbs) WebSockets.
* `21119`: Relay Server (hbbr) WebSockets.
