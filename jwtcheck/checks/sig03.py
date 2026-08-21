"""SIG-03: RS256 to HS256 algorithm confusion (only for RSA targets)."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify, forge_hs256, get_header_alg
from ._common import is_accepted, login_token

CHECK_ID = "SIG-03"
ASYMMETRIC = ("RS", "ES", "PS")
TITLE = "Algorithm confusion (RS256 to HS256)"
FIX = "Pin the expected algorithm so a public key cannot be used as an HMAC secret."


def run(client):
    cfg = client.config
    token = login_token(client)
    alg = get_header_alg(token) or ""

    if not alg.startswith(ASYMMETRIC):
        return _skipped(f"Target signs with {alg or 'an unknown alg'}, not RSA, so this attack does not apply.")
    if not cfg.public_key:
        return _skipped("No public key is configured to attempt the confusion.")

    with open(cfg.public_key, "rb") as f:
        public_key = f.read()

    forged = forge_hs256(decode_no_verify(token), public_key)
    resp = client.get(cfg.user_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="high",
        title=TITLE,
        explanation=(
            "The server accepted an HS256 token signed with its own RSA public key, "
            "so an attacker can forge tokens using the public key as the secret."
            if vulnerable
            else "The server rejected an HS256 token signed with the RSA public key."
        ),
        remediation=FIX,
        evidence=to_evidence(resp),
    )


def _skipped(reason):
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.SKIPPED,
        severity="info",
        title=TITLE,
        explanation=reason,
        remediation=FIX,
        evidence=None,
    )
