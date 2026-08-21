"""Load and validate a target config.

The config is the only thing that changes between targets. Nothing about a
target is hardcoded in the tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class Config:
    name: str
    base_url: str
    login_path: str
    credentials: dict
    token_from: dict      # how the login response carries the token
    send_token: dict      # how to send a token on a protected request
    user_path: str
    admin_path: str
    claims: dict          # names of the subject and role claims, plus the admin value
    expected_issuer: str | None
    expected_audience: str | None
    wordlist: str | None = None      # optional path for the brute-force passwd list
    public_key: str | None = None    # optional path to the RSA public key, for SIG-03


REQUIRED_TOP = ["name", "base_url", "login", "send_token", "endpoints", "claims"]


def load_config(path):
    with open(path) as f:
        raw = json.load(f)
    _validate(raw)
    expected = raw.get("expected", {})
    return Config(
        name=raw["name"],
        base_url=raw["base_url"].rstrip("/"),
        login_path=raw["login"]["path"],
        credentials=raw["login"]["credentials"],
        token_from=raw["login"]["token_from"],
        send_token=raw["send_token"],
        user_path=raw["endpoints"]["user"],
        admin_path=raw["endpoints"]["admin"],
        claims=raw["claims"],
        expected_issuer=expected.get("issuer"),
        expected_audience=expected.get("audience"),
        wordlist=raw.get("wordlist"),
        public_key=raw.get("public_key"),
    )


def _validate(raw):
    missing = [k for k in REQUIRED_TOP if k not in raw]
    if missing:
        raise ValueError(f"config missing keys: {', '.join(missing)}")

    for key in ("path", "credentials", "token_from"):
        if key not in raw["login"]:
            raise ValueError(f"config login missing key: {key}")

    for key in ("user", "admin"):
        if key not in raw["endpoints"]:
            raise ValueError(f"config endpoints missing key: {key}")

    for key in ("subject", "role", "admin_value"):
        if key not in raw["claims"]:
            raise ValueError(f"config claims missing key: {key}")

    if "via" not in raw["send_token"]:
        raise ValueError("config send_token missing key: via")
