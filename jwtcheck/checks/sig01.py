"""SIG-01: server accepts an unsigned alg:none token."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify, forge_alg_none

CHECK_ID = "SIG-01"


def run(client):
    cfg = client.config
    token, _ = client.login()
    if not token:
        raise RuntimeError("login did not return a token")

    claims = decode_no_verify(token)
    forged = forge_alg_none(claims)
    resp = client.get(cfg.user_path, forged)
    accepted = 200 <= resp.status_code < 300

    if accepted:
        explanation = (
            "The server accepted a token with alg:none and no signature. "
            "Anyone can forge a token without knowing the secret."
        )
    else:
        explanation = "The server rejected the unsigned alg:none token."

    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if accepted else Verdict.SAFE,
        severity="critical",
        title="Unsigned token accepted (alg:none)",
        explanation=explanation,
        remediation="Pin the expected algorithm and reject alg:none tokens.",
        evidence=to_evidence(resp),
    )
