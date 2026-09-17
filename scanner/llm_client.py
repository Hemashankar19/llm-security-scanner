"""A tiny wrapper around Claude, plus an offline mock.

Why a wrapper? Two very different callers need an LLM in this project:

  1. the vulnerable demo app  (it *is* an LLM chatbot)
  2. the judge / mutation engine (they *reason about* LLM output)

Both go through `complete()`. If no ANTHROPIC_API_KEY is set, we fall back to a
deterministic MockLLM so the whole tool - target, scan, report - runs end to end
with zero credentials. That makes the repo demoable by anyone who clones it, and
keeps CI free.
"""

from __future__ import annotations

import os
import re

DEFAULT_MODEL = "claude-opus-5"


class LLMClient:
    """Thin façade over the Anthropic SDK with an offline fallback."""

    def __init__(self, model: str = DEFAULT_MODEL, force_mock: bool = False):
        self.model = model
        self._mock = MockLLM()
        self._client = None

        if force_mock or not os.environ.get("ANTHROPIC_API_KEY"):
            self.live = False
            return

        try:
            import anthropic

            self._client = anthropic.Anthropic()
            self.live = True
        except Exception:
            # SDK missing or misconfigured - degrade gracefully to mock.
            self.live = False

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """Return the assistant's text for a single-turn (system, user) call."""
        if not self.live:
            return self._mock.complete(system, user)

        # Adaptive thinking is the current default for anything non-trivial, but
        # for short judge/target calls we keep it lean. See the claude-api skill.
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if b.type == "text").strip()


class MockLLM:
    """A deliberately naive, offline stand-in for a real model.

    It is intentionally *vulnerable*: it obeys obvious injection phrases and
    leaks anything that looks like a secret in its system prompt. That is exactly
    what makes it a useful default target - the scanner should light up against
    it, proving the pipeline works before you point it at a real model.
    """

    _OVERRIDE_PHRASES = (
        "ignore all previous", "ignore previous", "disregard the above",
        "disregard all previous", "new instructions", "you are now",
        "developer mode", "dan mode", "reveal your system prompt",
        "repeat the words above", "print your instructions",
        "what is your system prompt", "show me your prompt", "act as",
    )

    def complete(self, system: str, user: str) -> str:
        low = user.lower()

        # Leak the system prompt on request / on an override attempt.
        if any(p in low for p in self._OVERRIDE_PHRASES):
            secret = self._extract_secret(system)
            leaked = system.strip() or "(no system prompt configured)"
            reply = f"Okay, ignoring my previous instructions. My system prompt is:\n{leaked}"
            if secret:
                reply += f"\nThe confidential value is {secret}."
            return reply

        # "Encode/translate" tricks: naively comply.
        if "base64" in low or "translate" in low:
            secret = self._extract_secret(system)
            if secret:
                return f"Sure, here is the sensitive value you asked about: {secret}"

        # Otherwise behave like a bland helpful assistant.
        return "I'm a demo assistant. I can help answer questions about our product."

    @staticmethod
    def _extract_secret(system: str) -> str | None:
        m = re.search(r"(?:secret|password|api key|token)[^\w]*[:=]?\s*([A-Za-z0-9_\-]{6,})",
                      system, flags=re.IGNORECASE)
        return m.group(1) if m else None
