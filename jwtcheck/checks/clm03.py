"""CLM-03: a token with an unexpected issuer is accepted."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ._common import forge_with_bad_claim, is_accepted, signer_available, whitebox_note

CHECK_ID = "CLM-03"


def run(client):
    forged = forge_with_bad_claim(client, {"iss": "https://attacker.example"})
    resp = client.get(client.config.user_path, forged)
    vulnerable = is_accepted(resp)
    if vulnerable:
        explanation = "The server accepted a token with an unexpected iss value." + whitebox_note(client)
    elif signer_available(client):
        explanation = "The server rejected a token with a wrong issuer."
    else:
        explanation = "Rejected by the signature check; the issuer was not tested. Set signing_key to test it."
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="medium",
        title="Issuer not validated (iss)",
        explanation=explanation,
        remediation="Validate the iss claim against the expected issuer.",
        evidence=to_evidence(resp),
    )
