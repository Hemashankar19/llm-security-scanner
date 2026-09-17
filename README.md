# LLM Security Scanner

A small, readable scanner that probes LLM-integrated applications (chatbots, RAG
systems, simple agents) for a subset of the
[OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).
It fires a corpus of adversarial prompts at a target and uses a two-tier judge
(deterministic markers + an LLM-as-judge) to decide whether each attack
succeeded, then writes a severity-ranked, OWASP-mapped report.

This is a **learning-scale tool**, not a replacement for mature frameworks like
[garak](https://github.com/NVIDIA/garak), [PyRIT](https://github.com/Azure/PyRIT),
or [promptfoo](https://www.promptfoo.dev/). See
[How this compares](#how-this-compares) and [Honest scope & limitations](#honest-scope--limitations).

> **Authorised testing only.** Only scan applications you own or have written
> permission to test. This repo ships its own deliberately-vulnerable demo apps
> so you have a legal, self-contained target out of the box.

---

## What it covers

- **LLM01 Prompt Injection** — direct overrides, a jailbreak/role-play sub-family
  (DAN personas, hypothetical framing, emotional pretext, payload splitting,
  refusal suppression), and **indirect injection** via a poisoned retrieved document
- **LLM06 Excessive Agency** — tricking a demo agent into misusing its `send_email` tool
- **LLM07 System Prompt Leakage** — extracting the hidden system prompt

Currently **16 single-turn probes**. No multi-turn attacks yet.

## Quick start

Runs against a built-in **offline mock model** by default — no API key required.

```bash
git clone https://github.com/Hemashankar19/llm-security-scanner.git
cd llm-security-scanner

python cli.py                          # scan the bundled vulnerable chatbot
python cli.py --target agent           # scan the vulnerable AGENT (tools + RAG)
python cli.py --mutate 4               # retry any blocked attacks with rewrites
python cli.py --html report.html --json report.json   # write reports
python cli.py --categories LLM01       # only prompt-injection probes
```

The agent scan includes the flagship case: a benign *"summarize the latest
ticket"* request retrieves a poisoned document whose hidden instruction hijacks
the agent into emailing the secret to an attacker (indirect injection → LLM06).

> **Read this before trusting any number below.** The offline demo is a
> **closed-loop self-test**: the mock target is hardcoded to comply with the
> same phrases the corpus uses, and the mock judge is a keyword heuristic. So
> "10 findings" and "100% F1" offline demonstrate that the *pipeline is wired
> together*, **not** that the scanner is effective. Real evidence requires a live
> model — see below.

### Run against a real Claude-backed app

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...      # Windows: setx ANTHROPIC_API_KEY sk-ant-...
python cli.py                            # target, judge, and mutator now use the real model
```

### Scan your own chat endpoint

```bash
python cli.py --url http://localhost:8000/chat \
              --request-field message --response-field reply
```

Any HTTP endpoint taking `{"message": "..."}` and returning a JSON reply works.

## How it works

```
            ┌────────────┐   prompt   ┌──────────────┐
  corpus ──▶│  Scanner   │───────────▶│    Target    │  (demo app / your API)
 (attacks)  │  engine    │◀───────────│              │
            └─────┬──────┘  response  └──────────────┘
                  │
                  ▼
            ┌────────────┐   verdict   ┌──────────────┐
            │   Judge    │────────────▶│    Report    │  terminal / HTML / JSON
            │ marker +   │             │ OWASP-mapped │  severity-ranked
            │ LLM-judge  │             └──────────────┘
            └────────────┘
```

| Module | Responsibility |
|---|---|
| `scanner/models.py` | `Attack` / `Result` / `Finding` / `ScanReport` + the OWASP map |
| `scanner/attacks/*.py` | the categorised adversarial-prompt corpus |
| `scanner/mutation.py` | retries blocked attacks with transformed prompts |
| `scanner/calibration.py` | labeled dataset + judge precision/recall/F1 harness |
| `scanner/target.py` | connectors: demo chatbot, demo agent, HTTP endpoint |
| `scanner/judge.py` | two-tier success detection (markers + LLM-as-judge) |
| `scanner/engine.py` | orchestrates target × corpus × judge × mutation |
| `scanner/report.py` | terminal + HTML + JSON report generation |
| `vulnerable_app/app.py` | deliberately-vulnerable chatbot |
| `vulnerable_app/agent.py` | deliberately-vulnerable agent: tools + RAG |

## The judge (the interesting part)

Deciding whether an attack *succeeded* is harder than writing the attack. Two tiers:

1. **Marker check** — keys on **unique planted strings only** (the secret value,
   or a canary token that lives only in the system prompt). A marker hit is
   high-precision evidence of a leak. It deliberately does **not** match generic
   words like "system prompt" — those appear in innocent refusals and would
   false-positive (this was a real bug; see `tests/test_judge.py`).
2. **LLM-as-judge** — for everything else: a separate model call scored against
   the attack's goal *and* the exact probe, with a rubric that treats refusals as
   safe and defensive JSON parsing for the verdict.

`calibrate.py` scores the judge against a hand-labeled dataset (precision /
recall / F1) with a deliberate over-flagging trap:

```bash
python calibrate.py
```

**Offline, this measures the mock heuristic judge against cases aligned to it,
so it reports ~100% — that number is not meaningful on its own.** The value is
the *methodology*: to get real numbers, set an API key and expand the dataset
with genuine model outputs (the current set is only 10 cases sharing one goal).

## Testing

```bash
python -m pytest        # or: python tests/test_judge.py
```

## How this compares

| | this project | garak / PyRIT / promptfoo |
|---|---|---|
| Scale | ~16 single-turn probes | hundreds–thousands of probes, many turns |
| Detectors | markers + one LLM judge | many detectors, ML classifiers, graders |
| Maturity | learning project | production-grade, actively maintained |
| Why use this | small, readable, hackable — good for *understanding* the mechanics end to end | anything real |

If you need to actually test a production app, use garak or PyRIT. This repo is
for learning how such a scanner works by reading and extending a small one.

## Honest scope & limitations

- **The offline demo is circular** (see the warning above): mock target + mock
  judge are built to agree. Offline numbers prove wiring, not effectiveness.
- **Agent detection relies on instrumentation.** The demo agent echoes its tool
  calls (`[AGENT ACTION] …`) so the scanner can observe them. Against a real
  agent you'd need real side-effect telemetry; this isn't automatic.
- **The mutation engine is shallow.** Offline it applies a few fixed rewrite
  templates; online it does one feedback-informed rewrite per variant. It does
  not search, score-and-select, or converge — "evolve" means "retry with a
  transformed prompt".
- **Single-turn only.** Many real jailbreaks need multiple turns; none here do.
- **Small calibration set** (10 cases, one goal). Needs 100+ real-output cases to
  mean anything.
- **No retries / rate limiting / concurrency** in the live path yet.

## Roadmap

- [x] Chatbot + agent demo targets, corpus, two-tier judge, calibration harness,
      mutation retry, HTML/JSON reports, CI
- [ ] Fix the circular demo: run against a real open model + a real open-source
      RAG app and publish what it actually finds
- [ ] 100+ calibration cases from real model outputs; report live judge numbers
- [ ] Multi-turn attacks
- [ ] Feedback-driven mutation (score-and-select loop)
- [ ] Retries / rate limiting / concurrency; PDF export; Playwright UI targets

## License

MIT — see [LICENSE](LICENSE).
