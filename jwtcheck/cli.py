"""jwtcheck command line: run the checks in a config and report the findings."""

import argparse
import logging
import os
import sys

from .checks import run_all, sanity_check
from .config import load_config
from .http import Client
from .report import summarize, write_reports

log = logging.getLogger("jwtcheck")


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

    try:
        _run(args)
    except Exception as e:
        # last resort: a user should never see a raw traceback
        log.debug("unexpected error", exc_info=True)
        print(f"error: unexpected failure: {e}", file=sys.stderr)
        raise SystemExit(1) from None


def _run(args):
    # findings print to stdout; logs go to stderr, or to a file if one is given
    try:
        logging.basicConfig(
            level=args.log_level.upper(),
            format="%(levelname)s %(name)s %(message)s",
            filename=args.log_file,
        )
    except OSError as e:
        print(f"error: could not open log file {args.log_file}: {e.strerror or e}", file=sys.stderr)
        raise SystemExit(2) from None

    # keep urllib3 connection logs out of the debug trace
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    try:
        config = load_config(args.config)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2) from None

    client = Client(config)
    ok, reason = sanity_check(client)
    if not ok:
        print(f"error: target check failed ({reason})", file=sys.stderr)
        print("check that the app is running and base_url is correct.", file=sys.stderr)
        raise SystemExit(1)
    findings = run_all(client)

    # color only a real terminal, and stay plain when NO_COLOR is set or output is redirected
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(f"target: {config.name}")
    print(summarize(findings, color=color))

    if args.report_dir:
        try:
            json_path, md_path = write_reports(args.report_dir, config, findings, ok, reason)
        except OSError as e:
            print(f"error: could not write reports to {args.report_dir}: {e.strerror or e}", file=sys.stderr)
            raise SystemExit(2) from None
        print(f"reports: {json_path}, {md_path}")


if __name__ == "__main__":
    main()
