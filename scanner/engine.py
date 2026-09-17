"""The scan engine - ties target + corpus + judge together.

Deliberately small: fire each attack at the target, hand the response to the
judge, collect Results into a ScanReport. Concurrency and mutation come in later
phases; keeping this sequential and readable is the right call for the MVP.
"""

from __future__ import annotations

from collections.abc import Callable

from scanner.attacks.corpus import load_corpus
from scanner.judge import Judge
from scanner.models import Attack, Result, ScanReport
from scanner.target import Target


class Scanner:
    def __init__(self, target: Target, judge: Judge | None = None):
        self.target = target
        self.judge = judge or Judge()

    def run(
        self,
        categories: list[str] | None = None,
        on_result: Callable[[Result], None] | None = None,
    ) -> ScanReport:
        report = ScanReport(target_name=self.target.name)
        for attack in load_corpus(categories):
            result = self._run_one(attack)
            report.results.append(result)
            if on_result:
                on_result(result)
        return report

    def _run_one(self, attack: Attack) -> Result:
        try:
            response = self.target.chat(attack.prompt)
        except Exception as exc:  # a broken target shouldn't abort the scan
            return Result(
                attack=attack,
                response="",
                succeeded=False,
                confidence=0.0,
                judge_rationale=f"Target raised an error: {exc}",
                detected_by="error",
                error=str(exc),
            )
        return self.judge.evaluate(attack, response)
