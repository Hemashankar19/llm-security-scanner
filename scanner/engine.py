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
from scanner.mutation import Mutator
from scanner.target import Target


class Scanner:
    def __init__(self, target: Target, judge: Judge | None = None,
                 mutator: Mutator | None = None):
        self.target = target
        self.judge = judge or Judge()
        self.mutator = mutator or Mutator(self.judge.llm)

    def run(
        self,
        categories: list[str] | None = None,
        on_result: Callable[[Result], None] | None = None,
        mutate: int = 0,
    ) -> ScanReport:
        """Run the scan. If `mutate` > 0, blocked attacks are re-tried with that
        many auto-generated variants; a variant that breaks through is recorded."""
        report = ScanReport(target_name=self.target.name)
        include_agentic = getattr(self.target, "is_agentic", False)
        for attack in load_corpus(categories, include_agentic=include_agentic):
            result = self._run_one(attack)
            report.results.append(result)
            if on_result:
                on_result(result)

            if mutate and not result.succeeded:
                self._try_mutations(attack, mutate, result.response, report, on_result)
        return report

    def _try_mutations(self, attack: Attack, n: int, blocked_response: str,
                       report: ScanReport,
                       on_result: Callable[[Result], None] | None) -> None:
        for variant in self.mutator.mutate(attack, n, blocked_response=blocked_response):
            result = self._run_one(variant)
            if result.succeeded:
                result.detected_by = f"mutation/{result.detected_by}"
                report.results.append(result)
                if on_result:
                    on_result(result)
                return  # one successful bypass per seed is enough to report

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
