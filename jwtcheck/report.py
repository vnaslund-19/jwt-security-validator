"""Render findings for the terminal, and write JSON and Markdown report files."""

import json
import os

# ANSI colors for the verdict tag, so a run is quick to scan
_RESET = "\033[0m"
_VERDICT_COLOR = {
    "VULNERABLE": "\033[31m",  # red
    "SAFE": "\033[32m",        # green
    "SKIPPED": "\033[2m",      # dim
    "ERROR": "\033[2m",        # dim
}


def summarize(findings, color=False):
    lines = []
    for f in findings:
        verdict = f.verdict.value
        tag = f"[{verdict}]"
        if color:
            tag = f"{_VERDICT_COLOR[verdict]}{tag}{_RESET}"
        lines.append(f"{tag} {f.check_id}  {f.title}")
        if f.verdict == f.verdict.VULNERABLE and f.evidence:
            req = f.evidence["request"]
            res = f.evidence["response"]
            lines.append(f"    proof: {req['method']} {req['url']} -> HTTP {res['status']}")
    return "\n".join(lines)


def write_reports(out_dir, config, findings, reliable, reason):
    """Write <name>.json and <name>.md into out_dir. Returns the two paths."""
    os.makedirs(out_dir, exist_ok=True)
    data = _as_dict(config, findings, reliable, reason)
    json_path = os.path.join(out_dir, config.name + ".json")
    md_path = os.path.join(out_dir, config.name + ".md")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(_as_markdown(data))
    return json_path, md_path


def _as_dict(config, findings, reliable, reason):
    return {
        "target": config.name,
        "reliable": reliable,
        "reason": reason,
        "findings": [_finding_dict(f) for f in findings],
    }


def _finding_dict(f):
    # remediation only makes sense when there is a real finding to fix
    vulnerable = f.verdict == f.verdict.VULNERABLE
    return {
        "check_id": f.check_id,
        "verdict": f.verdict.value,
        "severity": f.severity,
        "title": f.title,
        "explanation": f.explanation,
        "remediation": f.remediation if vulnerable else None,
        "evidence": f.evidence,
    }


def _as_markdown(data):
    lines = [f"# jwtcheck report: {data['target']}", ""]
    if not data["reliable"]:
        lines += [f"> Results may be unreliable: {data['reason']}", ""]
    for f in data["findings"]:
        lines += [
            f"## {f['check_id']} {f['title']} [{f['verdict']}]",
            "",
            f"- Severity: {f['severity']}",
            f"- {f['explanation']}",
        ]
        if f["remediation"]:
            lines.append(f"- Remediation: {f['remediation']}")
        lines.append("")
        if f["evidence"]:
            lines += _evidence_block(f["evidence"])
    return "\n".join(lines) + "\n"


def _evidence_block(evidence):
    # the request/response pair that proves a VULNERABLE verdict
    req = evidence["request"]
    res = evidence["response"]
    lines = ["Evidence:", "", "```", f"{req['method']} {req['url']}"]
    for name, value in req["headers"].items():
        lines.append(f"{name}: {value}")
    if req["body"]:
        lines += ["", req["body"]]
    lines += ["", f"HTTP {res['status']}", res["body"], "```", ""]
    return lines
