"""jwtcheck command line: run the checks in a config and report the findings."""

import argparse
import logging

from .checks import run_all, sanity_check
from .config import load_config
from .http import Client
from .report import summarize


def main():
    parser = argparse.ArgumentParser(prog="jwtcheck")
    parser.add_argument("--config", required=True, help="path to a target config JSON")
    parser.add_argument(
        "--log-level",
        default="warning",
        choices=["debug", "info", "warning", "error"],
        help="how much detail to log while checks run",
    )
    parser.add_argument(
        "--log-file",
        help="write logs here instead of the terminal",
    )
    args = parser.parse_args()

    # findings print to stdout; logs go to stderr, or to a file if one is given
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(levelname)s %(name)s %(message)s",
        filename=args.log_file,
    )

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
