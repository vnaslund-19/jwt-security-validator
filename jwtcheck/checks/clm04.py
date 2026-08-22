"""CLM-04: a token with an unexpected audience is accepted."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ._common import forge_with_bad_claim, is_accepted

CHECK_ID = "CLM-04"


def run(client):
    forged = forge_with_bad_claim(client, {"aud": "https://attacker.example"})
    resp = client.get(client.config.user_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="medium",
        title="Audience not validated (aud)",
        explanation=(
            "The server accepted a token with an unexpected aud value."
            if vulnerable
            else "The server rejected a token with a wrong audience."
        ),
        remediation="Validate the aud claim against the expected audience.",
        evidence=to_evidence(resp),
    )
