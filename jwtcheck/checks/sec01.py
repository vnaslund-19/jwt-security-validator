"""SEC-01: the HMAC secret is weak enough to brute-force from a wordlist."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import brute_force_secret, decode_no_verify, get_header_alg, resign
from ._common import is_accepted, login_token

CHECK_ID = "SEC-01"

WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "jwt",
    "secretkey", "test", "letmein", "qwerty", "password123", "key",
]


def run(client):
    cfg = client.config
    token = login_token(client)
    alg = get_header_alg(token) or ""

    if not alg.startswith("HS"):
        return _finding(
            Verdict.SKIPPED,
            f"Target signs with {alg or 'an unknown alg'}, not HMAC, so secret brute-force does not apply.",
            evidence=None,
        )

    secret = brute_force_secret(token, _load_wordlist(cfg), alg)
    if secret is None:
        return _finding(Verdict.SAFE, "The signing secret was not found in the wordlist.", evidence=None)

    claims = decode_no_verify(token)
    claims[cfg.claims["role"]] = cfg.claims["admin_value"]
    forged = resign(claims, secret, alg)
    resp = client.get(cfg.admin_path, forged)
    accepted = is_accepted(resp)
    if accepted:
        explanation = (
            f"The signing secret '{secret}' was recovered from a wordlist and used to "
            "forge an admin token the server accepted."
        )
    else:
        explanation = f"The signing secret '{secret}' was recovered, but the forged admin token was rejected."
    return _finding(Verdict.VULNERABLE if accepted else Verdict.SAFE, explanation, to_evidence(resp))


def _load_wordlist(cfg):
    if not cfg.wordlist:
        return WEAK_SECRETS
    with open(cfg.wordlist, encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def _finding(verdict, explanation, evidence):
    return Finding(
        check_id=CHECK_ID,
        verdict=verdict,
        severity="critical",
        title="Weak HMAC secret",
        explanation=explanation,
        remediation="Use a long, random HMAC secret.",
        evidence=evidence,
    )
