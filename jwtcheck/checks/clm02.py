"""CLM-02: a token used before its nbf time is accepted."""

import time

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify
from ._common import forge_with_bad_claim, is_accepted, login_token, signer_available, utc_time, whitebox_note

CHECK_ID = "CLM-02"


def run(client):
    cfg = client.config

    # forge a token with nbf in the future when a signature can be made.
    now = int(time.time())
    future = now + 3600
    forged = forge_with_bad_claim(client, {"nbf": future})
    resp = client.get(cfg.user_path, forged)
    if is_accepted(resp):
        explanation = (
            f"The server accepted a token not valid until {utc_time(future)} (now {utc_time(now)})."
            + whitebox_note(client)
        )
        return _finding(Verdict.VULNERABLE, explanation, resp)

    # a server that signs properly can't be attacked by forging, but if it issues
    # a token with nbf in the future the real token can be replayed before then.
    replay, nbf = _replay_before_nbf(client)
    if replay is not None and is_accepted(replay):
        explanation = f"The server accepted a token not valid until {utc_time(nbf)} (now {utc_time(int(time.time()))})."
        return _finding(Verdict.VULNERABLE, explanation, replay)

    if signer_available(client) or replay is not None:
        explanation = "The server rejected a token used before its nbf time."
    else:
        explanation = "Rejected by the signature check; the nbf was not tested. Set signing_key to test it."
    return _finding(Verdict.SAFE, explanation, replay or resp)


def _replay_before_nbf(client):
    token = login_token(client)
    nbf = decode_no_verify(token).get("nbf")
    if nbf is None or nbf <= int(time.time()):
        return None, None
    return client.get(client.config.user_path, token), nbf


def _finding(verdict, explanation, resp):
    return Finding(
        check_id=CHECK_ID,
        verdict=verdict,
        severity="medium",
        title="Not-yet-valid token accepted (nbf)",
        explanation=explanation,
        remediation="Reject tokens used before their nbf time.",
        evidence=to_evidence(resp),
    )
