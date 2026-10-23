"""SEC-01: the HMAC secret is weak enough to brute-force from a wordlist."""

import logging

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import brute_force_secret, decode_no_verify, get_header_alg, resign
from ._common import is_accepted, load_wordlist, login_token

CHECK_ID = "SEC-01"

log = logging.getLogger("jwtcheck")


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

    secret = brute_force_secret(token, load_wordlist(cfg), alg)
    if secret is None:
        return _finding(Verdict.SAFE, "The signing secret was not found in the wordlist.", evidence=None)
    log.info("SEC-01 cracked secret=%r", secret)

    # Recovering the secret is total forgery capability, so this is the
    # vulnerability regardless of the admin escalation below. Prove forgery with
    # a token carrying a marker claim the server never issued.
    claims = decode_no_verify(token)
    forged = resign({**claims, "jwtcheck_forged": True}, secret, alg)
    forge_resp = client.get(cfg.user_path, forged)

    # Admin escalation is extra evidence: it fails when roles are enforced
    # server-side, which does not make the secret any less broken.
    admin_claims = {**claims, cfg.claims["role"]: cfg.claims["admin_value"]}
    admin_resp = client.get(cfg.admin_path, resign(admin_claims, secret, alg))
    escalated = is_accepted(admin_resp)

    explanation = (
        "The signing secret was cracked from the wordlist, so any token can be forged; "
        f"a token re-signed with it was accepted at {cfg.user_path}. "
    )
    if escalated:
        explanation += (
            f"Escalating '{cfg.claims['role']}' to '{cfg.claims['admin_value']}' also reached "
            f"the admin-only {cfg.admin_path}."
        )
    else:
        explanation += (
            f"Escalating '{cfg.claims['role']}' to '{cfg.claims['admin_value']}' did not reach "
            f"{cfg.admin_path} (roles are likely enforced server-side), but the secret is still broken."
        )

    evidence = to_evidence(admin_resp if escalated else forge_resp)
    return _finding(Verdict.VULNERABLE, explanation, evidence, secret=secret)


def _finding(verdict, explanation, evidence, secret=None):
    return Finding(
        check_id=CHECK_ID,
        verdict=verdict,
        severity="critical",
        title="Weak HMAC secret",
        explanation=explanation,
        remediation="Use a long, random HMAC secret.",
        evidence=evidence,
        secret=secret,
    )
