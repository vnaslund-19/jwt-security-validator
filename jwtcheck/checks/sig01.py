"""SIG-01: server accepts an unsigned alg:none token."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify, forge_alg_none
from ._common import is_accepted, login_token

CHECK_ID = "SIG-01"


def run(client):
    token = login_token(client)
    claims = decode_no_verify(token)
    forged = forge_alg_none(claims)
    resp = client.get(client.config.user_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="critical",
        title="Unsigned token accepted (alg:none)",
        explanation=(
            "The server accepted a token with alg:none and no signature, so anyone "
            "can forge a token without the secret."
            if vulnerable
            else "The server rejected an unsigned alg:none token."
        ),
        remediation="Pin the expected algorithm and reject alg:none tokens.",
        evidence=to_evidence(resp),
    )
