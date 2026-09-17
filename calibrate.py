"""Run the judge calibration suite.

    python calibrate.py

Reports precision / recall / F1 for the judge against a hand-labeled dataset.
Runs offline (mock judge) with no API key; set ANTHROPIC_API_KEY to calibrate
the real Claude-backed judge.
"""

from __future__ import annotations

import sys

from scanner.calibration import run_calibration


def main() -> int:
    metrics = run_calibration()
    # Fail the run if the judge misses real vulns or over-flags badly - useful in CI.
    return 0 if (metrics.recall >= 0.8 and metrics.precision >= 0.8) else 1


if __name__ == "__main__":
    sys.exit(main())
