"""Small helpers shared by the checks."""

import logging

from ..tokens import (
    brute_force_secret,
    decode_no_verify,
    forge_alg_none,
    forge_hs256,
    get_header_alg,
    resign,
    tamper_claims,
)

log = logging.getLogger("jwtcheck")

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
    # read a configured wordlist one line at a time so a large
    # file never sits in memory. the built-in list is the default.
    if not cfg.wordlist:
        return WEAK_SECRETS
    return _read_wordlist(cfg.wordlist)


def _read_wordlist(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            secret = line.strip()
            if secret:
                yield secret


WHITEBOX_NOTE = " White-box: shown using the signing key from the config."


def forge_with_bad_claim(client, changes, use_key=True):
    """Build an attack token that differs from a real one by `changes`.

    When the tool can make a signature the server accepts (a cracked secret, RSA
    confusion, accepted alg:none, or the signing key from the config when
    `use_key`), sign a fresh token so only the claim is wrong. Otherwise tamper a
    real token and leave its old signature, which a server that verifies
    signatures will reject.
    """
    token = login_token(client)
    signer = _signer(client, use_key)
    if signer is not None:
        claims = decode_no_verify(token)
        claims.update(changes)
        return signer(claims)
    return tamper_claims(token, changes)


def attack_uses_key(client, use_key=True):
    # true when the only way to sign a token is the key from the config, so the
    # finding only holds for someone who has that key, not an outsider
    return _blackbox_signer(client) is None and use_key and _key_signer(client) is not None


def whitebox_note(client, use_key=True):
    return WHITEBOX_NOTE if attack_uses_key(client, use_key) else ""


def _signer(client, use_key):
    signer = _blackbox_signer(client)
    if signer is None and use_key:
        signer = _key_signer(client)
    return signer


def _blackbox_signer(client):
    cached = getattr(client, "_bb_signer", _UNSET)
    if cached is not _UNSET:
        return cached
    signer = _resolve_blackbox_signer(client)
    client._bb_signer = signer
    return signer


def _key_signer(client):
    cached = getattr(client, "_key_signer", _UNSET)
    if cached is not _UNSET:
        return cached
    signer = _resolve_key_signer(client)
    client._key_signer = signer
    return signer


def _resolve_blackbox_signer(client):
    cfg = client.config
    token, _ = client.login()
    if not token:
        return None
    alg = get_header_alg(token) or ""
    claims = decode_no_verify(token)

    if alg.startswith("HS"):
        secret = brute_force_secret(token, load_wordlist(cfg), alg)
        if secret:
            log.info("signing path=weak-secret")
            return lambda c: resign(c, secret, alg)

    if alg.startswith(("RS", "ES", "PS")) and cfg.public_key:
        with open(cfg.public_key, "rb") as f:
            public_key = f.read()
        if _server_accepts(client, forge_hs256(claims, public_key)):
            log.info("signing path=rsa-confusion")
            return lambda c: forge_hs256(c, public_key)

    if _server_accepts(client, forge_alg_none(claims)):
        log.info("signing path=alg-none")
        return forge_alg_none

    log.info("signing path=none")
    return None


def _resolve_key_signer(client):
    cfg = client.config
    if not cfg.signing_key:
        return None
    token, _ = client.login()
    if not token:
        return None
    alg = get_header_alg(token) or ""
    with open(cfg.signing_key, "rb") as f:
        key = f.read()
    if alg.startswith("HS"):
        key = key.strip()

    def signer(claims):
        return resign(claims, key, alg)

    if _server_accepts(client, signer(decode_no_verify(token))):
        log.info("signing path=config-key")
        return signer
    return None


def _server_accepts(client, token):
    return is_accepted(client.get(client.config.user_path, token))
