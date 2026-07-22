FROM python:3.12-slim

WORKDIR /app

# Kerberos/GSSAPI headers + runtime for pyspnego's kerberos backend.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libkrb5-dev krb5-user \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 21114

# SSO expects: env SSO_SPN (e.g. HTTP/rustdesk.iterum.lv), env KRB5_KTNAME
# (path to the mounted keytab), and /etc/krb5.conf with the realm->KDC mapping.
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:21114", "--access-logfile", "-", "--error-logfile", "-", "server:app"]
