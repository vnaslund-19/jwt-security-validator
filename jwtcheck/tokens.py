"""JWT helpers used by the checks."""

import base64
import json

import jwt


def decode_no_verify(token):
    """Read a token's claims without checking its signature."""
    return jwt.decode(token, options={"verify_signature": False})


def forge_alg_none(claims):
    """Build an unsigned token (alg:none) carrying the given claims."""
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url(claims)
    return f"{header}.{payload}."


def _b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
