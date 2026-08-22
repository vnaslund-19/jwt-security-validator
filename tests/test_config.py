"""load_config accepts every real config and rejects malformed ones."""

import copy
import glob
import json
import os

import pytest

from jwtcheck.config import load_config

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "configs")


def _base():
    with open(os.path.join(CONFIG_DIR, "header-auth-vulnerable.json")) as f:
        return json.load(f)


def _write_bad(tmp_path, mutate):
    cfg = copy.deepcopy(_base())
    mutate(cfg)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    return str(path)


def test_every_real_config_loads():
    for path in glob.glob(os.path.join(CONFIG_DIR, "*.json")):
        load_config(path)


def test_missing_required_key_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_config(_write_bad(tmp_path, lambda c: c.pop("claims")))


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_config(_write_bad(tmp_path, lambda c: c.update({"endpoint": "/typo"})))


def test_bad_transport_enum_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_config(_write_bad(tmp_path, lambda c: c["send_token"].update({"via": "queryparam"})))


def test_json_source_without_field_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_config(_write_bad(tmp_path, lambda c: c["login"]["token_from"].pop("field")))
