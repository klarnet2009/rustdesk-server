"""Kerberos/SPNEGO acceptance. Turns a Negotiate token into a verified AD principal.

No DB, no Flask, no LDAP here — single responsibility. The keytab is chosen by
the system GSSAPI via the KRB5_KTNAME environment variable; the SPN is supplied
by the caller from config (never from the HTTP Host header).
"""

import base64

try:
    import spnego
    SPNEGO_AVAILABLE = True
except ImportError:
    spnego = None
    SPNEGO_AVAILABLE = False


class SsoError(Exception):
    pass


def validate_negotiate_token(token_b64, spn):
    """Verify a base64 SPNEGO token against `spn` ("HTTP/<host>"). Returns principal."""
    if not SPNEGO_AVAILABLE:
        raise SsoError("pyspnego not installed")
    service, _, hostname = spn.partition('/')
    if not service or not hostname:
        raise SsoError(f"invalid SPN: {spn!r}")
    try:
        token = base64.b64decode(token_b64, validate=True)
    except Exception as e:
        raise SsoError(f"invalid base64 token: {e}")
    try:
        ctx = spnego.server(hostname=hostname, service=service)
        ctx.step(token)
    except Exception as e:
        raise SsoError(f"GSSAPI acceptance failed: {e}")
    if not ctx.complete:
        raise SsoError("Negotiate handshake incomplete (multi-leg/NTLM not supported)")
    principal = getattr(ctx, 'client_principal', None)
    if not principal:
        raise SsoError("no client principal in completed context")
    return principal
