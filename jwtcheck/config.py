"""Load and validate a target config.

The config is the only thing that changes between targets. Nothing about a
target is hardcoded in the tool. config-schema.json is the contract for a
config and doubles as its documentation; a config can point at it with a
"$schema" key to get editor validation while it is written.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import jsonschema

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config-schema.json")


def _load_schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


CONFIG_SCHEMA = _load_schema()


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
    try:
        jsonschema.validate(raw, CONFIG_SCHEMA)
    except jsonschema.ValidationError as e:
        location = ".".join(str(p) for p in e.absolute_path) or "config"
        raise ValueError(f"invalid config at {location}: {e.message}") from e
