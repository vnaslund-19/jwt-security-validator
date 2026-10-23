"""ACL-02: the sub claim can be swapped to impersonate another identity."""

from ..findings import Finding, Verdict
from ..http import to_evidence
from ..tokens import decode_no_verify
from ._common import forge_with_bad_claim, is_accepted, login_token

CHECK_ID = "ACL-02"


def run(client):
    cfg = client.config
    sub_claim = cfg.claims["subject"]
    token = login_token(client)
    original = decode_no_verify(token).get(sub_claim)
    target = _swap_target(client, sub_claim, original)

    # if the endpoint shows the identity, the swap can be confirmed by finding the
    # new name in the response. if it shows nothing, the verdict falls back to
    # whether the token was accepted (the explanation says which).
    echoes_identity = str(original) in client.get(cfg.user_path, token).text

    # don't use the signing key here: with the key you could make a token for any
    # user, so the swap would always succeed and prove nothing. test only what an
    # outsider without the key could do.
    forged = forge_with_bad_claim(client, {sub_claim: target}, use_key=False)
    resp = client.get(cfg.user_path, forged)
    accepted = is_accepted(resp)
    confirmed = accepted and echoes_identity and str(target) in resp.text
    assumed = accepted and not echoes_identity

    if confirmed:
        explanation = (
            f"The server returned '{target}' for a token with {sub_claim} swapped from "
            f"'{original}', confirming identity is read straight from the token."
        )
    elif assumed:
        explanation = (
            f"The server accepted a token with {sub_claim} swapped from '{original}' to "
            f"'{target}'. The endpoint does not reveal identity, so this is inferred from "
            "acceptance, not a confirmed swap."
        )
    else:
        explanation = "The server did not accept a swapped identity."

    return Finding(
        check_id=CHECK_ID,
        verdict=Verdict.VULNERABLE if (confirmed or assumed) else Verdict.SAFE,
        severity="high",
        title="Identity swap via sub claim",
        explanation=explanation,
        remediation="Verify the signature so the sub claim cannot be swapped.",
        evidence=to_evidence(resp),
    )


def _swap_target(client, sub_claim, original):
    # swap to a real second account if the config names one, so apps that reject
    # an unknown user are still tested. otherwise make up a name.
    creds = client.config.impersonate
    if creds:
        other, _ = client.login(creds)
        if other:
            return decode_no_verify(other).get(sub_claim)
    return f"{original}-impersonated"
