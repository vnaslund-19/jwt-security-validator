"""jwtcheck command line: run the checks in a config and report the findings."""

import argparse

from .checks import REGISTRY
from .config import load_config
from .findings import Finding, Verdict
from .http import Client
from .report import summarize


def main():
    parser = argparse.ArgumentParser(prog="jwtcheck")
    parser.add_argument("--config", required=True, help="path to a target config JSON")
    args = parser.parse_args()

    config = load_config(args.config)
    client = Client(config)

    findings = []
    for check_id, run in REGISTRY.items():
        try:
            findings.append(run(client))
        except Exception as e:
            findings.append(Finding(
                check_id=check_id,
                verdict=Verdict.ERROR,
                severity="info",
                title="check failed",
                explanation=str(e),
                remediation="",
                evidence=None,
            ))

    print(f"target: {config.name}")
    print(summarize(findings))


if __name__ == "__main__":
    main()
