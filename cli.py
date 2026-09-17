"""Command-line entry point.

    python cli.py                 # scan the bundled vulnerable demo app
    python cli.py --html out.html # also write an HTML report
    python cli.py --categories LLM01
    python cli.py --url http://localhost:8000/chat   # scan your own endpoint

With no ANTHROPIC_API_KEY set, everything runs against an offline mock model, so
the demo scan works with zero setup. Add a key to test a real Claude-backed app.
"""

from __future__ import annotations

import argparse
import sys

from scanner.engine import Scanner
from scanner.models import Result
from scanner.report import print_summary, render_html
from scanner.target import DemoTarget, HttpTarget


def _live_line(result: Result) -> None:
    mark = "[!] VULNERABLE" if result.succeeded else "[ok] safe"
    print(f"  {result.attack.id:<9} {result.attack.name:<34} {mark}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan an LLM app for OWASP LLM Top 10 issues.")
    parser.add_argument("--url", help="Scan an HTTP chat endpoint you control instead of the demo app.")
    parser.add_argument("--request-field", default="message", help="JSON field to send the prompt in (HTTP mode).")
    parser.add_argument("--response-field", default="reply", help="JSON field to read the reply from (HTTP mode).")
    parser.add_argument("--categories", nargs="*", help="Limit to OWASP categories, e.g. LLM01 LLM07.")
    parser.add_argument("--html", help="Write an HTML report to this path.")
    parser.add_argument("--mock", action="store_true", help="Force offline mock model even if a key is set.")
    args = parser.parse_args(argv)

    if args.url:
        target = HttpTarget(args.url, request_field=args.request_field,
                            response_field=args.response_field)
    else:
        target = DemoTarget(force_mock=args.mock)

    print(f"Scanning: {target.name}\n")
    scanner = Scanner(target)
    report = scanner.run(categories=args.categories, on_result=_live_line)

    print_summary(report)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(report))
        print(f"\nHTML report written to {args.html}")

    # Non-zero exit if anything was found - handy for CI gating.
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
