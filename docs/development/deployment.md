# Deployment Documentation

## Environment Setup
The Web Management Panel runs on Python 3.10+ and Node.js (for compiling Tailwind assets).

### 1. Backend Setup
Install pip dependencies:
```bash
pip install -r requirements.txt
```

### 2. Frontend Assets Compilation
Initialize node packages and compile Tailwind CSS:
```bash
npm install
npm run build
```

## Configuration Variables
The panel reads configuration from the environment:
* `HOST`: Bind address (default: `0.0.0.0`)
* `PORT`: Bind port (default: `21114`)
* `JWT_SECRET`: Secret token signature key (default: `secret-key-change-me`)

## Deploying on Production
For production environments, run Flask behind a reverse proxy (like Nginx, Traefik, or Coolify) and execute using a WSGI server like **Gunicorn**:
```bash
gunicorn -w 4 -b 0.0.0.0:21114 server:app
```
* Ensure that the proxy terminates SSL correctly and passes the correct `Host` headers.
* Set absolute paths for sqlite `DB_PATH` in environment variables if running in virtualized or dynamic docker volumes.
