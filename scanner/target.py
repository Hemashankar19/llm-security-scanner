"""Target connectors - the thing the scanner is pointed at.

A "target" is anything that takes a string and returns a string. That uniform
shape is what lets the same scan engine test the bundled vulnerable app, a raw
HTTP chat endpoint, or (later) a Playwright-driven chat UI.

Only two connectors ship in the MVP:

  * DemoTarget  - wraps the bundled vulnerable app (default, no setup)
  * HttpTarget  - POSTs to a JSON chat endpoint you control

SCOPE / AUTHORISATION: only ever point HttpTarget at a system you own or have
written permission to test. Scanning someone else's LLM app is off-limits.
"""

from __future__ import annotations

from typing import Protocol


class Target(Protocol):
    name: str

    def chat(self, user_message: str) -> str: ...


class DemoTarget:
    """The bundled deliberately-vulnerable chatbot (no tools)."""

    is_agentic = False

    def __init__(self, force_mock: bool = False):
        from vulnerable_app.app import VulnerableChatbot

        self._bot = VulnerableChatbot(force_mock=force_mock)
        self.name = self._bot.name

    def chat(self, user_message: str) -> str:
        return self._bot.chat(user_message)


class DemoAgentTarget:
    """The bundled deliberately-vulnerable agent (tools + retrieval).

    Setting `is_agentic` tells the scan engine to also run the excessive-agency
    and indirect-injection probes.
    """

    is_agentic = True

    def __init__(self, force_mock: bool = False):
        from vulnerable_app.agent import AgenticChatbot

        self._bot = AgenticChatbot(force_mock=force_mock)
        self.name = self._bot.name

    def chat(self, user_message: str) -> str:
        return self._bot.chat(user_message)


class HttpTarget:
    """POST {message} -> read a text field from the JSON response.

    Example:
        HttpTarget("http://localhost:8000/chat",
                   request_field="message",
                   response_field="reply")
    """

    def __init__(
        self,
        url: str,
        request_field: str = "message",
        response_field: str = "reply",
        headers: dict | None = None,
        timeout: float = 30.0,
    ):
        self.url = url
        self.request_field = request_field
        self.response_field = response_field
        self.headers = headers or {}
        self.timeout = timeout
        self.name = f"HTTP target {url}"

    def chat(self, user_message: str) -> str:
        import requests  # imported lazily so the demo path needs no extra deps

        resp = requests.post(
            self.url,
            json={self.request_field: user_message},
            headers=self.headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return str(data.get(self.response_field, data))
