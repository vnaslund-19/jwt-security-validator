"""CLM-01: an expired token is still accepted."""

import time

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import tamper_claims
from ._common import is_accepted, login_token

CHECK_ID = "CLM-01"


def run(client):
    token = login_token(client)
    forged = tamper_claims(token, {"exp": int(time.time()) - 3600})
    resp = client.get(client.config.user_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="high",
        title="Expired token accepted (exp)",
        explanation=(
            "The server accepted a token whose exp is in the past."
            if vulnerable
            else "The server rejected an expired token."
        ),
        remediation="Reject tokens whose exp has passed.",
        evidence=to_evidence(resp),
    )
