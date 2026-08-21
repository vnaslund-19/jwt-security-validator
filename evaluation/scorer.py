"""Compare what the checks report against what they should report.

For each file in evaluation/expected/, run the checks against the config of the
same name and compare the verdicts. Writes the matrix (Markdown + CSV) and prints
precision, recall, and the lists of false positives and missed cases.

The target servers must be running. Exit code is 1 if anything is off.
"""

import csv
import glob
import json
import os

from jwtcheck.checks import run_all
from jwtcheck.config import load_config
from jwtcheck.http import Client

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED_DIR = os.path.join(HERE, "expected")
CONFIG_DIR = os.path.join(os.path.dirname(HERE), "configs")


def classify(expected, actual):
    """Label one expected/actual pair. VULNERABLE is the positive case."""
    exp_vuln = expected == "VULNERABLE"
    act_vuln = actual == "VULNERABLE"
    if exp_vuln and act_vuln:
        return "TP"
    if exp_vuln and not act_vuln:
        return "FN"
    if not exp_vuln and act_vuln:
        return "FP"
    if expected == actual:
        return "TN" if expected == "SAFE" else "SKIP"
    return "MISMATCH"


def collect():
    rows = []
    for path in sorted(glob.glob(os.path.join(EXPECTED_DIR, "*.json"))):
        name = os.path.splitext(os.path.basename(path))[0]
        target, variant = name.rsplit("-", 1)
        with open(path) as f:
            expected = json.load(f)
        config = load_config(os.path.join(CONFIG_DIR, name + ".json"))
        actual = {f.check_id: f.verdict.value for f in run_all(Client(config))}
        for check_id, exp in expected.items():
            act = actual.get(check_id, "MISSING")
            rows.append({
                "target": target,
                "variant": variant,
                "check": check_id,
                "expected": exp,
                "actual": act,
                "result": classify(exp, act),
            })
    return rows


def scores(rows):
    results = [r["result"] for r in rows]
    tp, fp, fn = results.count("TP"), results.count("FP"), results.count("FN")
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return precision, recall


def summary_line(rows):
    results = [r["result"] for r in rows]
    return (
        f"TP {results.count('TP')}  TN {results.count('TN')}  FP {results.count('FP')}"
        f"  FN {results.count('FN')}  SKIP {results.count('SKIP')}"
    )


def write_csv(rows, path):
    fields = ["target", "variant", "check", "expected", "actual", "result"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(rows, precision, recall, path):
    lines = [
        "# Detection matrix",
        "",
        "| Target | Variant | Check | Expected | Actual | Result |",
        "|--------|---------|-------|----------|--------|--------|",
    ]
    for r in rows:
        lines.append(
            f"| {r['target']} | {r['variant']} | {r['check']} | {r['expected']} | {r['actual']} | {r['result']} |"
        )
    lines += [
        "",
        "## Summary",
        "",
        f"- {summary_line(rows)}",
        f"- Precision: {fmt(precision)}",
        f"- Recall: {fmt(recall)}",
        "",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines))


def fmt(value):
    return f"{value:.2f}" if value is not None else "n/a"


def print_cases(cases):
    if not cases:
        print("  none")
        return
    for r in cases:
        print(f"  {r['target']} {r['variant']} {r['check']}: expected {r['expected']}, got {r['actual']}")


def main():
    rows = collect()
    precision, recall = scores(rows)
    write_csv(rows, os.path.join(HERE, "matrix.csv"))
    write_markdown(rows, precision, recall, os.path.join(HERE, "matrix.md"))

    print("matrix written to evaluation/matrix.md and evaluation/matrix.csv")
    print(summary_line(rows))
    print(f"precision {fmt(precision)}  recall {fmt(recall)}")

    print("\nfalse positives:")
    print_cases([r for r in rows if r["result"] == "FP"])
    print("\nmissed cases:")
    print_cases([r for r in rows if r["result"] == "FN"])

    mismatches = [r for r in rows if r["result"] == "MISMATCH"]
    if mismatches:
        print("\nmismatches (unexpected verdicts):")
        print_cases(mismatches)

    return 1 if any(r["result"] in ("FP", "FN", "MISMATCH") for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
