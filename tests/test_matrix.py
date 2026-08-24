"""Start each target app and check its verdicts against evaluation/expected/.

Every target is a small standalone Flask server. This starts them all, runs the
full check set against each one the way the CLI would, and compares the result
to the expected verdicts. A change that breaks a check, or makes one fire on a
remediated target, fails here. Run from the repo root so the file paths in the
configs (wordlist, public key) resolve.
"""

import json
import os
import socket
import subprocess
import sys
import time

import pytest
import requests

from jwtcheck.checks import run_all, sanity_check
from jwtcheck.config import load_config
from jwtcheck.http import Client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(ROOT, "configs")
EXPECTED_DIR = os.path.join(ROOT, "evaluation", "expected")


def target_names():
    # one expected/<name>.json per target, e.g. "header-auth-vulnerable"
    files = sorted(f for f in os.listdir(EXPECTED_DIR) if f.endswith(".json"))
    return [f.removesuffix(".json") for f in files]


def app_file(name):
    # "header-auth-vulnerable" -> targets/header-auth/vulnerable/app.py
    target, variant = name.rsplit("-", 1)
    return os.path.join(ROOT, "targets", target, variant, "app.py")


def config_file(name):
    return os.path.join(CONFIG_DIR, name + ".json")


def free_port():
    # bind to port 0 so the OS hands back an unused port, then release it
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until_up(base_url, deadline):
    while time.time() < deadline:
        try:
            requests.get(base_url, timeout=0.3)  # a 404 for "/" still means it is up
            return True
        except requests.ConnectionError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="session")
def servers():
    # give each app its own free port via PORT, so a run never collides with
    # another server (a demo target, a previous run) and needs no fixed ports
    running = {}
    procs = []
    for name in target_names():
        port = free_port()
        procs.append(subprocess.Popen(
            [sys.executable, app_file(name)],
            env={**os.environ, "PORT": str(port)},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ))
        running[name] = f"http://127.0.0.1:{port}"

    deadline = time.time() + 20  # total time to let every server come up
    for name, base_url in running.items():
        if not wait_until_up(base_url, deadline):
            raise RuntimeError(f"{name} did not start")
    yield running
    for proc in procs:
        proc.terminate()
    for proc in procs:
        proc.wait()


@pytest.mark.parametrize("name", target_names())
def test_verdicts_match_expected(name, servers):
    config = load_config(config_file(name))
    config.base_url = servers[name]  # talk to the port this run started, not the config default
    client = Client(config)

    ok, reason = sanity_check(client)
    assert ok, f"{name} failed the sanity check: {reason}"

    actual = {f.check_id: f.verdict.value for f in run_all(client)}
    with open(os.path.join(EXPECTED_DIR, name + ".json")) as expected_file:
        expected = json.load(expected_file)

    wrong = {}
    for check, want in expected.items():
        got = actual.get(check)
        if got != want:
            wrong[check] = {"expected": want, "actual": got}
    assert not wrong, f"{name}: {wrong}"
