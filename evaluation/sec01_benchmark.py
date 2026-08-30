"""Measure SEC-01 brute-force throughput against a real wordlist.

SEC-01 recovers a weak HMAC secret by trying each entry of a wordlist against a
captured token. This times that loop so the throughput and crack times are
measured, not guessed. It calls the tool's own load_wordlist and
brute_force_secret, so it times the real code path.

Two runs:
  - a miss: the token is signed with a random secret that is not in the list, so
    every entry is tried. That is the worst case and gives the raw throughput.
  - a hit near the bottom of the list: the token is signed with a real secret
    that sits close to the end, so the scan runs almost the whole way before it
    cracks. This shows the loop recovers a late secret and times how long it takes.

The common secrets near the top (password, trustno1) are reported by their
position, with the crack time worked out from the throughput, since timing a
sub-millisecond hit is not meaningful.

Takes an optional wordlist path, defaulting to rockyou.txt in the repo root. The
wordlist is not part of the repo; if it is missing the script says so. Writes
evaluation/sec01-benchmark.txt and prints the same report.
"""

import os
import platform
import re
import secrets
import sys
import time

import jwt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jwtcheck.checks._common import load_wordlist  # noqa: E402
from jwtcheck.tokens import brute_force_secret, resign  # noqa: E402

ALGORITHM = "HS256"
COMMON = ["123456", "password", "trustno1"]  # well-known secrets near the top of the list
_CLEAN = re.compile(r"^[A-Za-z0-9]{6,}$")     # printable, so it reads clearly in the report


class _Cfg:
    """Minimal stand-in for a Config: load_wordlist only reads .wordlist."""

    def __init__(self, path):
        self.wordlist = path


def _token(secret):
    return resign({"sub": "benchmark"}, secret, ALGORITHM)


def _positions(words, probes):
    # one pass: first 1-based index of each probe word, if present
    wanted, found = set(probes), {}
    for i, word in enumerate(words, start=1):
        if word in wanted and word not in found:
            found[word] = i
            if len(found) == len(wanted):
                break
    return found


def _bottom_secret(words):
    # pick a clean secret close to the bottom: scan up from the end for a printable
    # entry whose first occurrence is in the last 1%, so the scan runs almost the whole list
    n = len(words)
    for i in range(n - 1, -1, -1):
        cand = words[i]
        if _CLEAN.match(cand):
            first = words.index(cand)
            if first > n * 0.99:
                return cand, first + 1
    return words[-1], words.index(words[-1]) + 1


def run(path):
    # read the whole wordlist in. the benchmark needs the positions
    # and then scans the same words twice
    t0 = time.perf_counter()
    words = list(load_wordlist(_Cfg(path)))
    load_secs = time.perf_counter() - t0
    count = len(words)

    common = _positions(words, COMMON)
    bottom_secret, bottom_pos = _bottom_secret(words)

    t1 = time.perf_counter()
    miss = brute_force_secret(_token(secrets.token_hex(32)), words, ALGORITHM)
    miss_secs = time.perf_counter() - t1
    assert miss is None, "the miss secret should not be in the wordlist"

    t2 = time.perf_counter()
    hit = brute_force_secret(_token(bottom_secret), words, ALGORITHM)
    hit_secs = time.perf_counter() - t2
    assert hit == bottom_secret, "the bottom secret should have been recovered"

    return {
        "path": path,
        "count": count,
        "load_secs": load_secs,
        "miss_secs": miss_secs,
        "rate": count / miss_secs if miss_secs else 0,
        "common": common,
        "bottom_secret": bottom_secret,
        "bottom_pos": bottom_pos,
        "hit_secs": hit_secs,
    }


def format_report(r):
    rate = r["rate"]
    lines = [
        "SEC-01 brute-force benchmark",
        "",
        f"host      : {platform.platform()}",
        f"python    : {platform.python_version()}",
        f"PyJWT     : {jwt.__version__}",
        f"wordlist  : {r['path']}",
        "",
        f"entries          : {r['count']:,}",
        f"load into memory : {r['load_secs']:.1f} s",
        f"full scan (miss) : {r['miss_secs']:.1f} s   (secret absent, every entry tried)",
        f"throughput       : {rate:,.0f} candidates/sec",
        "",
        "common secrets near the top, crack time from throughput (position / rate):",
    ]
    for probe in COMMON:
        pos = r["common"].get(probe)
        if pos is None:
            lines.append(f"  {probe:<12} not in list")
        else:
            lines.append(f"  {probe:<12} position {pos:>12,}   ~{pos / rate:.3f} s")
    lines += [
        "",
        "a secret near the bottom, cracked and timed:",
        f"  {r['bottom_secret']:<12} position {r['bottom_pos']:>12,}   {r['hit_secs']:.1f} s   (recovered)",
    ]
    return "\n".join(lines) + "\n"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "rockyou.txt"
    if not os.path.isfile(path):
        print(f"wordlist not found: {path}", file=sys.stderr)
        return 1
    report = format_report(run(path))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sec01-benchmark.txt")
    with open(out, "w") as f:
        f.write(report)
    print(report, end="")
    print(f"written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
