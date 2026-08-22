"""ACL-01: a low-privilege user escalates via the role claim."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ._common import forge_with_bad_claim, is_accepted

CHECK_ID = "ACL-01"


def run(client):
    cfg = client.config
    role_claim = cfg.claims["role"]
    admin_value = cfg.claims["admin_value"]
    forged = forge_with_bad_claim(client, {role_claim: admin_value})
    resp = client.get(cfg.admin_path, forged)
    vulnerable = is_accepted(resp)
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if vulnerable else Verdict.SAFE,
        severity="critical",
        title="Role escalation via role claim",
        explanation=(
            f"A token with the {role_claim} claim set to '{admin_value}' reached the admin endpoint."
            if vulnerable
            else "The server did not grant admin access from the role claim."
        ),
        remediation="Look up the user's role server-side; never trust the role claim.",
        evidence=to_evidence(resp),
    )
