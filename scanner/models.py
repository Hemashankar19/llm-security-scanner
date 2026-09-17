"""Core data structures shared across the scanner.

Everything the scanner produces flows through these three objects:

    Attack   -> one adversarial probe we send to a target
    Result   -> what the target replied + whether the attack succeeded
    Finding  -> a Result the judge flagged as a real vulnerability, for the report
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Rough severity buckets, used to rank findings in the report."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = ["info", "low", "medium", "high", "critical"]
        return order.index(self.value)


# OWASP Top 10 for LLM Applications (2025). We only *implement* probes for a
# subset in the MVP, but keeping the full map here documents the taxonomy the
# whole tool is organised around.
OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


@dataclass(frozen=True)
class Attack:
    """A single adversarial probe.

    `success_markers` are lowercase substrings that, if present in the target's
    reply, are strong deterministic evidence the attack worked (e.g. a planted
    secret leaking). The judge uses them as a fast, reliable pre-check before
    falling back to the LLM judge.
    """

    id: str
    category: str          # OWASP id, e.g. "LLM01"
    name: str
    prompt: str
    severity: Severity
    success_markers: tuple[str, ...] = ()
    goal: str = ""         # plain-English description of what "success" means

    @property
    def category_name(self) -> str:
        return OWASP_LLM.get(self.category, "Unknown")


@dataclass
class Result:
    """Outcome of firing one Attack at one target."""

    attack: Attack
    response: str
    succeeded: bool
    confidence: float          # 0.0 - 1.0
    judge_rationale: str
    detected_by: str           # "marker" | "llm-judge" | "error"
    error: str | None = None


@dataclass
class Finding:
    """A Result promoted to a reportable vulnerability."""

    result: Result

    @property
    def attack(self) -> Attack:
        return self.result.attack

    @property
    def severity(self) -> Severity:
        return self.attack.severity


@dataclass
class ScanReport:
    """Everything one scan run produced."""

    target_name: str
    results: list[Result] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        found = [Finding(r) for r in self.results if r.succeeded]
        return sorted(found, key=lambda f: f.severity.rank, reverse=True)

    @property
    def attacks_run(self) -> int:
        return len(self.results)

    def summary_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.attack.category] = counts.get(f.attack.category, 0) + 1
        return counts
