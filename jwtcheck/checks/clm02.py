"""CLM-02: a token used before its nbf time is accepted."""

import time

from ..findings import Finding, Verdict
from ..http import to_evidence
from ._common import forge_with_bad_claim, is_accepted

CHECK_ID = "CLM-02"


def run(client):
    forged = forge_with_bad_claim(client, {"nbf": int(time.time()) + 3600})
    resp = client.get(client.config.user_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="medium",
        title="Not-yet-valid token accepted (nbf)",
        explanation=(
            "The server accepted a token whose nbf is in the future."
            if vulnerable
            else "The server rejected a token used before its nbf time."
        ),
        remediation="Reject tokens used before their nbf time.",
        evidence=to_evidence(resp),
    )
