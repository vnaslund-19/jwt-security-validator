"""JWT helpers used by the checks."""

import base64
import json
import warnings

import jwt


def decode_no_verify(token):
    """Read a token's claims without checking its signature."""
    return jwt.decode(token, options={"verify_signature": False})


def get_header_alg(token):
    return jwt.get_unverified_header(token).get("alg")


def forge_alg_none(claims):
    """Build an unsigned token (alg:none) carrying the given claims."""
    header = _b64url_encode({"alg": "none", "typ": "JWT"})
    payload = _b64url_encode(claims)
    return f"{header}.{payload}."


def tamper_claims(token, changes):
    """Change payload claims but keep the original header and signature."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(_b64url_decode(payload_b64))
    payload.update(changes)
    return f"{header_b64}.{_b64url_encode(payload)}.{sig_b64}"


def resign(claims, secret, algorithm):
    """Sign claims into a fresh, valid token."""
    with warnings.catch_warnings():
        # this tool works with weak keys on purpose, so the length warning is noise
        warnings.filterwarnings("ignore", category=jwt.InsecureKeyLengthWarning)
        return jwt.encode(claims, secret, algorithm=algorithm)


def brute_force_secret(token, candidates, algorithm):
    """Return the first candidate that verifies the token, else None."""
    options = {"verify_exp": False, "verify_nbf": False, "verify_iss": False, "verify_aud": False}
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=jwt.InsecureKeyLengthWarning)
        for secret in candidates:
            try:
                jwt.decode(token, secret, algorithms=[algorithm], options=options)
                return secret
            except jwt.InvalidTokenError:
                continue
    return None


def _b64url_encode(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(segment):
    # JWT drops base64 padding; add '=' back so the length is a multiple of 4
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)
