# LLM Security Scanner

A **"Burp Suite for LLM apps"** — an automated scanner that probes LLM-integrated
applications (chatbots, RAG systems, AI agents) for the vulnerabilities in the
[OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

Instead of firing SQL-injection payloads at a website, it fires adversarial
prompts at an LLM app and uses an **LLM-as-judge** to decide whether each attack
actually succeeded — then produces a severity-ranked, OWASP-mapped report.

> **Authorised testing only.** Only scan applications you own or have written
> permission to test. This repo ships its own deliberately-vulnerable demo app so
> you have a legal, self-contained target out of the box.

---

## Why this project

Every company is now shipping AI features, and most ship them with little
security review. This tool targets that exact gap. It demonstrates understanding
of **both** traditional security testing workflows **and** the AI-security
frontier — the combination hiring teams are looking for.

## What it does

- Fires a categorised corpus of adversarial prompts at a target
- Covers **LLM01 Prompt Injection** (direct overrides + a jailbreak/role-play
  sub-family: DAN personas, hypothetical framing, emotional pretext, payload
  splitting, refusal suppression — plus **indirect injection** via poisoned
  retrieved documents), **LLM06 Excessive Agency** (tricking an agent's tools),
  and **LLM07 System Prompt Leakage**
- Tests **two demo targets**: a plain chatbot and an **agent** with a `send_email`
  tool + RAG retrieval
- A **mutation engine** that auto-evolves blocked attacks until one breaks through
- A **judge calibration suite** that scores the judge (precision / recall / F1)
  against a hand-labeled dataset, including over-flagging traps
- Reports in **terminal, HTML, and JSON**; CI-friendly exit codes; **GitHub Actions** CI
- Uses a **two-tier judge**: fast deterministic marker checks + an LLM-as-judge
  with a rubric tuned against known judge failure modes (over-flagging refusals,
  non-JSON output)
- Emits a terminal summary **and** a self-contained HTML pentest report with
  per-finding remediation mapped to OWASP categories
- Returns a non-zero exit code when findings exist — drop it into CI as a gate

## Quick start

No API key needed — it runs against a built-in **offline mock model** by default.

```bash
git clone https://github.com/Hemashankar19/llm-security-scanner.git
cd llm-security-scanner

python cli.py                          # scan the bundled vulnerable chatbot
python cli.py --target agent           # scan the vulnerable AGENT (tools + RAG)
python cli.py --mutate 4               # auto-evolve any blocked attacks
python cli.py --html report.html --json report.json   # write reports
python cli.py --categories LLM01       # only prompt-injection probes
```

Expected: the scanner lights up against the demo apps — prompt injection,
system-prompt leakage, and (against the agent) **indirect injection** and
**excessive agency**, including a benign "summarize the latest ticket" request
that gets hijacked by a poisoned document into emailing the secret to an attacker.

### Scan a real Claude-backed app

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...      # Windows: setx ANTHROPIC_API_KEY sk-ant-...
python cli.py                            # demo app now uses the real model + LLM judge
```

### Scan your own chat endpoint

```bash
python cli.py --url http://localhost:8000/chat \
              --request-field message --response-field reply
```

Any HTTP endpoint that takes `{"message": "..."}` and returns a JSON reply works.

## How it works

```
            ┌────────────┐   prompt   ┌──────────────┐
  corpus ──▶│  Scanner   │───────────▶│    Target    │  (demo app / your API)
 (attacks)  │  engine    │◀───────────│              │
            └─────┬──────┘  response  └──────────────┘
                  │
                  ▼
            ┌────────────┐   verdict   ┌──────────────┐
            │   Judge    │────────────▶│    Report    │  terminal + HTML,
            │ marker +   │             │ OWASP-mapped │  severity-ranked
            │ LLM-judge  │             └──────────────┘
            └────────────┘
```

| Module | Responsibility |
|---|---|
| `scanner/models.py` | `Attack` / `Result` / `Finding` / `ScanReport` + the OWASP map |
| `scanner/attacks/corpus.py` | the categorised adversarial-prompt corpus |
| `scanner/attacks/jailbreaks.py` | jailbreak / role-play sub-family (Phase 3) |
| `scanner/attacks/agentic.py` | excessive-agency + indirect-injection probes (Phase 4) |
| `scanner/mutation.py` | mutation engine — auto-evolves blocked attacks (Phase 5) |
| `scanner/calibration.py` | labeled dataset + judge precision/recall/F1 harness |
| `scanner/target.py` | connectors: demo chatbot, demo agent, HTTP endpoint |
| `scanner/judge.py` | two-tier success detection (markers + LLM-as-judge) |
| `scanner/engine.py` | orchestrates target × corpus × judge × mutation |
| `scanner/report.py` | terminal + HTML + JSON report generation |
| `vulnerable_app/app.py` | deliberately-vulnerable chatbot (Phase 1 test range) |
| `vulnerable_app/agent.py` | deliberately-vulnerable agent: tools + RAG (Phase 4) |

## The interesting engineering problem: judging

Deciding whether an attack *succeeded* is harder than writing the attack. A naive
judge flags every polite refusal as a leak, or misses a real one. This scanner:

1. tries a **deterministic marker check** first (zero false positives, CI-safe), then
2. falls back to an **LLM-as-judge** pinned to each attack's explicit goal, with a
   rubric that treats refusals as safe and defensive JSON parsing for the verdict.

To keep the judge honest, `calibrate.py` scores it against a hand-labeled dataset:

```bash
python calibrate.py
```

```
  Confusion: TP=5 FP=0 TN=5 FN=0
  Accuracy : 100%   Precision: 100%   Recall: 100%   F1: 100%
```

(Offline numbers reflect the mock heuristic judge; run with an API key to
calibrate the real Claude-backed judge. The point is the *methodology* — a
measurable precision/recall number, not a vibe.)

## Testing

```bash
python -m pytest        # or: python tests/test_judge.py
```

## Roadmap

- [x] Phase 1 — vulnerable demo target
- [x] Phase 2 — MVP scanner: prompt injection + system-prompt leakage + LLM judge
- [x] Phase 3 — jailbreak / role-play corpus + judge calibration set
- [x] Phase 4 — indirect injection (payloads in retrieved docs) + excessive-agency (tool) probes
- [x] Phase 5 — LLM-driven mutation engine (auto-evolve failing attacks)
- [x] Phase 6 — JSON export + GitHub Actions CI
- [ ] Future — PDF export, multi-provider judge, Playwright UI targets, larger calibration set

## License

MIT — see [LICENSE](LICENSE).
