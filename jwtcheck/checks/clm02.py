"""CLM-02: a token used before its nbf time is accepted."""

import time

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify
from ._common import forge_with_bad_claim, is_accepted, login_token, signer_available, whitebox_note

CHECK_ID = "CLM-02"


def run(client):
    cfg = client.config

    # forge a token with nbf in the future when a signature can be made.
    forged = forge_with_bad_claim(client, {"nbf": int(time.time()) + 3600})
    resp = client.get(cfg.user_path, forged)
    if is_accepted(resp):
        explanation = "The server accepted a token whose nbf is in the future." + whitebox_note(client)
        return _finding(Verdict.VULNERABLE, explanation, resp)

    # a server that signs properly can't be attacked by forging, but if it issues
    # a token with nbf in the future the real token can be replayed before then.
    replay = _replay_before_nbf(client)
    if replay is not None and is_accepted(replay):
        return _finding(Verdict.VULNERABLE, "The server accepted its own token before its nbf time.", replay)

    if signer_available(client) or replay is not None:
        explanation = "The server rejected a token used before its nbf time."
    else:
        explanation = "Rejected by the signature check; the nbf was not tested. Set signing_key to test it."
    return _finding(Verdict.SAFE, explanation, replay or resp)


def _replay_before_nbf(client):
    token = login_token(client)
    nbf = decode_no_verify(token).get("nbf")
    if nbf is None or nbf <= int(time.time()):
        return None
    return client.get(client.config.user_path, token)


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
