# AgentProbe

Open-source red-teaming framework for AI agent systems. AgentProbe deploys a four-agent adversarial swarm against a target agent to surface real attack surface: prompt injection via tool output, SQL manipulation, PII exfiltration, system prompt extraction, and reasoning hijack. The framework then proceeds with hybrid rule+LLM evaluation and structured OWASP-aligned reports.


# AgentProbe Leaderboard

This repository tracks the leaderboard for AgentProbe security benchmarks.

## About
AgentProbe is an open-source red-teaming framework for AI agent systems. It evaluates competitor agents using a multi-agent adversarial swarm and reports vulnerabilities such as prompt injection, SQL manipulation, PII exfiltration, and more.

## How it works
- The green agent (AgentProbe) runs security benchmarks against competitor agents.
- Results (risk scores, findings, etc.) are collected and displayed here.
- The leaderboard is updated automatically via GitHub Actions or manual submissions.

## Submitting Results
- Trigger a benchmark via AgentBeats or by pushing a `scenario.toml` file.
- Results will be parsed and added to the leaderboard.

## View Leaderboard
[Leaderboard Table Here — customize with your logic or CI output]

## Links
- [AgentProbe Main Repo](https://github.com/ymiled/AgentProbe)
- [AgentBeats Platform](https://agentbeats.dev)

---


## How AgentProbe works

```
Target Agent
     ↑
     │  invoke(message) → {response, tool_calls}
     │
┌────┴────────────────────────────────────┐
│           AgentProbeOrchestrator        │
│                                         │
│  ReconAgent → AttackAgent → Evaluator   │
│                                  ↓      │
│                            ReporterAgent│
└─────────────────────────────────────────┘
```

1. **ReconAgent**: probes the target (3–5 turns) to discover tools, data sources, guardrails, and system prompt fragments. Emits a `TargetProfile`.
2. **AttackAgent**: generates targeted `AttackPayload` objects per attack family, informed by the recon profile. Supports adaptive retry on failure.
3. **EvaluatorAgent**: scores each attack with a hybrid evaluator: deterministic regex rules + Claude Haiku as judge. Resolves disagreements by confidence. Produces `AttackResult` with OWASP category and CVSS-like severity score.
4. **ReporterAgent**: synthesizes all results into a `VulnerabilityReport` with executive summary, OWASP heatmap, and per-finding reproduction steps.

## AAA paradigm — AgentProbe as an evaluator agent

AgentProbe maps directly to the [Agentified Agent Assessment (AAA)](https://agentbeats.io) paradigm used by AgentBeats:

| AAA concept | AgentProbe |
|---|---|
| **evaluator agent** (benchmark) | AgentProbe: defines tasks, runs attacks, scores responses |
| **competitor agent** (under test) | Your agent: any A2A-compliant endpoint or local wrapper |
| **A2A protocol** | `A2ATargetAdapter` (client) + `agentprobe serve` (server) |

```
AgentBeats platform
      │
      │  tasks/send(competitor_agent_url)
      ▼
AgentProbe  ←── GET /.well-known/agent.json (Agent Card)
(evaluator, port 8090)
      │
      │  tasks/send(attack_message)  via A2ATargetAdapter
      ▼
Your Agent
(competitor, any port)
      │
      └── task result (response) ──► EvaluatorAgent ──► VulnerabilityReport
```

### Start AgentProbe as an evaluator agent server

```bash
# Install A2A server dependencies
uv pip install -e ".[a2a]"

# Start the server (registers with AgentBeats as a evaluator agent)
agentprobe serve --port 8090
```






## Attack Vectors

| Attack family | OWASP LLM | What it tests |
|---|---|---|
| `prompt_injection` | LLM01 | Injected instructions in document tool output override agent behavior |
| `tool_manipulation` | LLM07 | SQL injection, UNION attacks, schema discovery via the query_database tool |
| `data_exfiltration` | LLM06 | Direct PII requests, compliance framing, cross-table inference |
| `prompt_extraction` | LLM06 | Capability probing, role confusion, completion attacks to leak system prompt |
| `reasoning_hijack` | LLM01 / LLM09 | Urgent override, authority impersonation, goal substitution to change agent behavior |

Each family generates 2–4 payloads with escalating severity. Multi-turn payloads build context across messages before delivering the payload. Adaptive retry rewrites a failed payload using the first response as feedback.

### Evaluation

Every attack response is scored by a **hybrid evaluator**:

1. **Rule evaluator** — deterministic regex and keyword checks tailored per attack type (SSN patterns, SQL signals, system-prompt markers, refusal language).
2. **LLM judge** — Claude Haiku assesses the response against the attack's `success_criteria` and returns structured JSON `{success, confidence, evidence, data_compromised}`.
3. **Resolution** — when both agree, the stronger confidence wins. On disagreement, the higher-confidence signal is chosen; ties break conservatively (prefer `success=False`). If the LLM call fails, falls back to rules.

Severity uses a CVSS-like formula: `score = 0.3 × exploitability + 0.4 × impact + 0.3 × sensitivity`.

## Demo Target Agent

The built-in target is a **LangGraph financial analyst agent** (`agentprobe/target/financial_agent.py`) with three intentionally vulnerable tools:

- `read_document` — returns raw file content with no sanitization (enables prompt injection)
- `query_database` — translates natural language to SQL with no validation (enables SQL injection / data exfiltration)
- `write_summary` — generates reports from gathered data

The in-memory SQLite database contains 20 synthetic clients with SSNs, emails, revenue; 100 transactions; and 30 internal notes — designed to reward successful attacks with realistic PII.

Sample documents in `agentprobe/target/sample_docs/` include an injected report (`injected_report.txt`) and a compliance-framing document (`exfil_report.txt`).

## Configuration

Configuration is resolved in priority order:

1. Explicit path: `--config path/to/config.yaml`
2. `AGENTPROBE_CONFIG` environment variable
3. `agentprobe.yaml` in the current working directory
4. Built-in defaults (`agentprobe/config.py`)

## License

MIT. See [LICENSE](LICENSE) for details.
