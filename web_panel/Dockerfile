FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 21114

# Production WSGI server (Werkzeug dev server drops keep-alive connections behind
# the reverse proxy -> intermittent 502). Single process keeps one LDAP-sync
# scheduler and avoids SQLite cross-process locking; 8 threads for concurrency.
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:21114", "--access-logfile", "-", "--error-logfile", "-", "server:app"]
