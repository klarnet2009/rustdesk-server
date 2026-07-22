FROM python:3.12-slim

WORKDIR /app

# Kerberos/GSSAPI headers + runtime for pyspnego's kerberos backend.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libkrb5-dev krb5-user \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Kerberos realm/KDC config (non-secret) baked in so GSSAPI finds it at the
# default /etc/krb5.conf. The service keytab is NOT baked — it is provided at
# runtime via the ./data/web_panel volume as /app/data/rustdesk.keytab (KRB5_KTNAME).
COPY krb5.conf /etc/krb5.conf

EXPOSE 21114

# SSO activation (once the keytab is in place): set env SSO_SPN=HTTP/rustdesk.iterum.lv.
# Until SSO_SPN is set, /api/login-sso returns 501 and clients fall back to manual login.
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:21114", "--access-logfile", "-", "--error-logfile", "-", "server:app"]
