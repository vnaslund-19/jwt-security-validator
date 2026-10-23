"""ACL-01: a low-privilege user escalates via the role claim."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ._common import forge_with_bad_claim, is_accepted, signer_available, whitebox_note

CHECK_ID = "ACL-01"


def run(client):
    cfg = client.config
    role_claim = cfg.claims["role"]
    admin_value = cfg.claims["admin_value"]
    forged = forge_with_bad_claim(client, {role_claim: admin_value})
    resp = client.get(cfg.admin_path, forged)
    vulnerable = is_accepted(resp)
    if vulnerable:
        explanation = (
            f"A token with the {role_claim} claim set to '{admin_value}' reached the admin endpoint."
            + whitebox_note(client)
        )
    elif signer_available(client):
        explanation = "The server did not grant admin access from the role claim."
    else:
        explanation = "Rejected by the signature check; the role was not tested. Set signing_key to test it."
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="critical",
        title="Role escalation via role claim",
        explanation=explanation,
        remediation="Look up the user's role server-side; never trust the role claim.",
        evidence=to_evidence(resp),
    )
