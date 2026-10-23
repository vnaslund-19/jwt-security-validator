"""CLM-01: an expired token is still accepted."""

import time

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify
from ._common import forge_with_bad_claim, is_accepted, login_token, signer_available, whitebox_note

CHECK_ID = "CLM-01"

MAX_WAIT = 10  # seconds; skip the replay path for a token that lives longer than this


def run(client):
    cfg = client.config

    # forge an already-expired token when a signature can be made.
    forged = forge_with_bad_claim(client, {"exp": int(time.time()) - 3600})
    resp = client.get(cfg.user_path, forged)
    if is_accepted(resp):
        explanation = "The server accepted a token whose exp is in the past." + whitebox_note(client)
        return _finding(Verdict.VULNERABLE, explanation, resp)

    # a server that signs properly can't be attacked by forging, but if it
    # issues a short-lived token the real token can be replayed once it expires.
    replay = _replay_after_expiry(client)
    if replay is not None and is_accepted(replay):
        return _finding(Verdict.VULNERABLE, "The server accepted its own token after its exp had passed.", replay)

    if signer_available(client) or replay is not None:
        explanation = "The server rejected an expired token."
    else:
        explanation = "Rejected by the signature check; expiry was not tested. Set signing_key to test it."
    return _finding(Verdict.SAFE, explanation, replay or resp)


def _replay_after_expiry(client):
    token = login_token(client)
    exp = decode_no_verify(token).get("exp")
    if exp is None:
        return None
    wait = exp - int(time.time())
    if wait < 0 or wait > MAX_WAIT:
        return None
    time.sleep(wait + 1)
    return client.get(client.config.user_path, token)


def _finding(verdict, explanation, resp):
    return Finding(
        check_id=CHECK_ID,
        verdict=verdict,
        severity="high",
        title="Expired token accepted (exp)",
        explanation=explanation,
        remediation="Reject tokens whose exp has passed.",
        evidence=to_evidence(resp),
    )
