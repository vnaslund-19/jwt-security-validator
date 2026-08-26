"""jwtcheck command line: run the checks in a config and report the findings."""

import argparse
import logging
import os
import sys

from .checks import run_all, sanity_check
from .config import load_config
from .http import Client
from .report import summarize, write_reports


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
    parser.add_argument(
        "--report-dir",
        help="write a JSON and a Markdown report for this run into this directory",
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

    # color only a real terminal, and stay plain when NO_COLOR is set or output is redirected
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(f"target: {config.name}")
    if not ok:
        print(f"WARNING: results may be unreliable ({reason})")
    print(summarize(findings, color=color))

    if args.report_dir:
        json_path, md_path = write_reports(args.report_dir, config, findings, ok, reason)
        print(f"reports: {json_path}, {md_path}")


if __name__ == "__main__":
    main()
