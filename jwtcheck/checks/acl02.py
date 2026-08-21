"""ACL-02: the sub claim can be swapped to impersonate another identity."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify, tamper_claims
from ._common import is_accepted, login_token

CHECK_ID = "ACL-02"


def run(client):
    cfg = client.config
    sub_claim = cfg.claims["subject"]
    token = login_token(client)
    original = decode_no_verify(token).get(sub_claim)
    swapped = f"{original}-impersonated"
    forged = tamper_claims(token, {sub_claim: swapped})
    resp = client.get(cfg.user_path, forged)
    vulnerable = is_accepted(resp) and swapped in resp.text
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="high",
        title="Identity swap via sub claim",
        explanation=(
            f"The server accepted a token with {sub_claim} changed from '{original}' to "
            f"'{swapped}', so identity is read straight from the token."
            if vulnerable
            else "The server did not accept a tampered identity claim."
        ),
        remediation="Verify the signature so the sub claim cannot be swapped.",
        evidence=to_evidence(resp),
    )
