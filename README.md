# AgentProbe

AgentProbe is a security project for red-teaming AI agent systems. It focuses on practical attack surfaces that appear when agents can read documents, query data, and call external tools.

## Installation

We use uv because it is significantly faster than traditional pip workflows and keeps dependency management consistent.

Install from source:

```bash
uv pip install -e .
```

Install from package index:

```bash
uv pip install agentprobe
```

## Quick Start

```bash
uv pip install agentprobe
agentprobe scan --target my_agent.py --attacks all
```

Set your API key before running scans (example on PowerShell):

```bash
$env:ANTHROPIC_API_KEY="your_key_here"
```

## Why AgentProbe

Most LLM testing focuses on model prompts in isolation. Real-world agent risks usually come from tool use and cross-system behavior. AgentProbe helps teams evaluate those risks with realistic, scenario-based testing.

## Current Scope

This repository currently includes:

- A configurable Python package foundation for agent security testing.
- Shared schemas for attacks, outcomes, severity, and OWASP-aligned categories.
- A demo financial target agent implemented with LangGraph and Anthropic.
- Sample tools and data sources designed to simulate common security weaknesses.
- Example documents used to test prompt injection and data exfiltration behavior.

## Repository Overview

- agentprobe/models: Data contracts for attack payloads, scan results, and vulnerability findings.
- agentprobe/target: Demo target agent, tool implementations, and in-memory database utilities.
- agentprobe/config.py: Default settings and YAML-based configuration loading.
- pyproject.toml and requirements.txt: Packaging metadata and dependency definitions.

## Security Research Focus

The project is oriented around categories such as:

- Prompt injection through untrusted document content.
- Tool manipulation in natural-language-to-database workflows.
- Sensitive data disclosure through broad query and reporting behavior.
- Prompt extraction and reasoning hijack patterns.

## Configuration

Configuration is loaded from defaults and can be overridden by a project-level YAML file or environment variables.

Important settings include:

- LLM provider and model details.
- Scan mode and enabled attack families.
- Defense toggles and detection thresholds.
- Output and logging preferences.

## License

MIT License. See LICENSE for details.