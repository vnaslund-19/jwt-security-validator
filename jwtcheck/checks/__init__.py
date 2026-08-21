"""The ID -> callable registry. Each check exposes run(client) -> Finding."""

from ..findings import Finding, Verdict
from . import acl01, acl02, clm01, clm02, clm03, clm04, sec01, sig01, sig02, sig03

REGISTRY = {
    sig01.CHECK_ID: sig01.run,
    sig02.CHECK_ID: sig02.run,
    sig03.CHECK_ID: sig03.run,
    sec01.CHECK_ID: sec01.run,
    clm01.CHECK_ID: clm01.run,
    clm02.CHECK_ID: clm02.run,
    clm03.CHECK_ID: clm03.run,
    clm04.CHECK_ID: clm04.run,
    acl01.CHECK_ID: acl01.run,
    acl02.CHECK_ID: acl02.run,
}


def run_all(client):
    """Run every check, turning an unexpected error into an ERROR finding."""
    findings = []
    for check_id, run in REGISTRY.items():
        try:
            findings.append(run(client))
        except Exception as exc:
            findings.append(Finding(
                check_id=check_id,
                verdict=Verdict.ERROR,
                severity="info",
                title="check failed",
                explanation=str(exc),
                remediation="",
                evidence=None,
            ))
    return findings
