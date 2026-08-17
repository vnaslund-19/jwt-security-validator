"""Render findings for the terminal."""


def summarize(findings):
    lines = []
    for f in findings:
        lines.append(f"[{f.verdict.value}] {f.check_id}  {f.title}")
        if f.verdict == f.verdict.VULNERABLE and f.evidence:
            req = f.evidence["request"]
            res = f.evidence["response"]
            lines.append(f"    proof: {req['method']} {req['url']} -> HTTP {res['status']}")
    return "\n".join(lines)
