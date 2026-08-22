"""jwtcheck command line: run the checks in a config and report the findings."""

import argparse

from .checks import run_all, sanity_check
from .config import load_config
from .http import Client
from .report import summarize


def main():
    parser = argparse.ArgumentParser(prog="jwtcheck")
    parser.add_argument("--config", required=True, help="path to a target config JSON")
    args = parser.parse_args()

    config = load_config(args.config)
    client = Client(config)
    ok, reason = sanity_check(client)
    findings = run_all(client)

    print(f"target: {config.name}")
    if not ok:
        print(f"WARNING: results may be unreliable ({reason})")
    print(summarize(findings))


if __name__ == "__main__":
    main()
