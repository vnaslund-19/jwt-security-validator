"""SIG-03: RS256 to HS256 algorithm confusion. Only applies to RSA targets."""

from ..findings import Finding, Verdict
from ..tokens import get_header_alg
from ._common import login_token

CHECK_ID = "SIG-03"
ASYMMETRIC = ("RS", "ES", "PS")


def run(client):
    alg = get_header_alg(login_token(client)) or "unknown"
    if alg.startswith(ASYMMETRIC):
        explanation = f"Target signs with {alg} but no public key is configured to attempt the confusion."
    else:
        explanation = f"Target signs with {alg}, not RSA, so RS256 to HS256 confusion does not apply."
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.SKIPPED,
        severity="info",
        title="Algorithm confusion (RS256 to HS256)",
        explanation=explanation,
        remediation="Pin the expected algorithm so an RSA public key cannot be used as an HMAC secret.",
        evidence=None,
    )
