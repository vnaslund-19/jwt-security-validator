"""Finding dataclass and Verdict enum. The contract everything else depends on."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"  # weakness exploited, evidence attached
    SAFE = "SAFE"              # check ran, attack rejected
    ERROR = "ERROR"            # check could not complete
    SKIPPED = "SKIPPED"        # not applicable to this config


@dataclass
class Finding:
    check_id: str
    verdict: Verdict
    severity: str
    title: str
    explanation: str
    remediation: str
    evidence: Optional[dict] = None  # request/response proving a VULNERABLE result
