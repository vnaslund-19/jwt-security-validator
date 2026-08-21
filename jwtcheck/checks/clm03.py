"""CLM-03: a token with an unexpected issuer is accepted."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import tamper_claims
from ._common import is_accepted, login_token

CHECK_ID = "CLM-03"


def run(client):
    token = login_token(client)
    forged = tamper_claims(token, {"iss": "https://attacker.example"})
    resp = client.get(client.config.user_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="medium",
        title="Issuer not validated (iss)",
        explanation=(
            "The server accepted a token with an unexpected iss value."
            if vulnerable
            else "The server rejected a token with a wrong issuer."
        ),
        remediation="Validate the iss claim against the expected issuer.",
        evidence=to_evidence(resp),
    )
