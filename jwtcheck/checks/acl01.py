"""ACL-01: a low-privilege user escalates via the role claim."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ._common import forge_with_bad_claim, is_accepted, login_token, signer_available, whitebox_note

CHECK_ID = "ACL-01"


def run(client):
    cfg = client.config
    role_claim = cfg.claims.get("role")
    admin_value = cfg.claims.get("admin_value")
    if not (cfg.admin_path and role_claim and admin_value):
        return _skipped("No admin endpoint and role claim configured, so role escalation was not tested.")

    # a forged role only proves escalation if the admin endpoint denies a normal
    # user to begin with. If it lets one in, there is no privilege boundary.
    baseline = client.get(cfg.admin_path, login_token(client))
    if is_accepted(baseline):
        return _skipped(
            f"The admin endpoint {cfg.admin_path} accepts a normal user, so there is no privilege "
            "boundary to test. Point endpoints.admin at an admin-only endpoint.",
            evidence=to_evidence(baseline),
        )

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


def _skipped(explanation, evidence=None):
    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.SKIPPED,
        severity="critical",
        title="Role escalation via role claim",
        explanation=explanation,
        remediation="",
        evidence=evidence,
    )
