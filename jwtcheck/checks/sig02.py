"""SIG-02: server accepts a token whose payload changed after signing."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import tamper_claims
from ._common import is_accepted, login_token

CHECK_ID = "SIG-02"


def run(client):
    token = login_token(client)
    forged = tamper_claims(token, {"tampered": True})
    resp = client.get(client.config.user_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="critical",
        title="Tampered token accepted",
        explanation=(
            "The server accepted a token whose payload was modified after signing, "
            "so the signature is not being verified."
            if vulnerable
            else "The server rejected a token with a modified payload."
        ),
        remediation="Verify the token signature on every request.",
        evidence=to_evidence(resp),
    )
