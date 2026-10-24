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
    claims: dict          # names of the subject and role claims, plus the admin value
    admin_path: str | None = None    # optional admin-only endpoint, for ACL-01
    impersonate: dict | None = None  # optional second real account, for the ACL-02 swap
    public_key: str | None = None    # optional path to the RSA public key, for SIG-03
    signing_key: str | None = None   # optional path to the app's signing key, for white-box claim tests


def load_config(path):
    try:
        with open(path) as f:
            raw = json.load(f)
    except OSError as e:
        raise ValueError(f"could not read config {path}: {e.strerror or e}") from None
    except json.JSONDecodeError as e:
        raise ValueError(f"config {path} is not valid JSON: {e}") from None
    _validate(raw)
    _check_paths(raw)
    token_from = raw["login"]["token_from"]
    return Config(
        name=raw.get("name") or os.path.splitext(os.path.basename(path))[0],
        base_url=raw["base_url"].rstrip("/"),
        login_path=raw["login"]["path"],
        credentials=raw["login"]["credentials"],
        token_from=token_from,
        send_token=_send_token(raw, token_from),
        user_path=raw["endpoints"]["user"],
        admin_path=raw["endpoints"].get("admin"),
        claims=raw["claims"],
        impersonate=raw["login"].get("impersonate"),
        public_key=raw.get("public_key"),
        signing_key=raw.get("signing_key"),
    )


def _send_token(raw, token_from):
    # a token read from a cookie is sent back in that same cookie by default
    send = raw.get("send_token")
    if send is not None:
        return send
    if token_from["source"] == "cookie":
        return {"via": "cookie", "name": token_from["name"]}
    raise ValueError("send_token is required unless the token is read from a cookie")


def _validate(raw):
    try:
        jsonschema.validate(raw, CONFIG_SCHEMA)
    except jsonschema.ValidationError as e:
        location = ".".join(str(p) for p in e.absolute_path) or "config"
        raise ValueError(f"invalid config at {location}: {e.message}") from e


def _check_paths(raw):
    # fail early with a clear message if an optional file path is wrong
    for key in ("public_key", "signing_key"):
        path = raw.get(key)
        if path is not None and not os.path.isfile(path):
            raise ValueError(f"{key} file not found: {path}")
