"""jwtcheck command line: run the checks in a config and report the findings."""

import argparse

from .checks import run_all
from .config import load_config
from .http import Client
from .report import summarize


def main():
    parser = argparse.ArgumentParser(prog="jwtcheck")
    parser.add_argument("--config", required=True, help="path to a target config JSON")
    args = parser.parse_args()

    config = load_config(args.config)
    findings = run_all(Client(config))

    print(f"target: {config.name}")
    print(summarize(findings))


if __name__ == "__main__":
    main()
