"""AgentProbe A2A 1.0 evaluator agent server.

Exposes AgentProbe as an A2A-compliant benchmark agent so it can be
registered on AgentBeats or called by any A2A-compatible client.

Endpoints
---------
GET  /.well-known/agent-card.json   Agent Card (A2A 1.0)
GET  /.well-known/agent.json        Alias for backward compatibility
POST /                              JSON-RPC 2.0 task handler
POST /reset                         Reset all state (required by AgentBeats controller)

Supported JSON-RPC methods (A2A 1.0)
-------------------------------------
SendMessage    Start a benchmark. Provide the competitor agent URL in a data part:
               {"competitor_agent_url": "http://...", "attacks": "all", "recon_messages": 4}
               Returns the task immediately with state="submitted"; the scan
               runs in a background thread.

GetTask        Poll for task status and results by task ID.

ListTasks      Returns all tasks with pagination metadata.

CancelTask     Mark a task as canceled (best-effort; running scan is not interrupted).

Task lifecycle
--------------
  submitted -> working -> completed
                       \-> failed

The completed artifact contains:
  - TextPart  : human-readable scan summary
  - DataPart  : {"scan_result": {...}, "vulnerability_report": {...}}

AgentBeats integration
-----------------------
Set $HOST and $AGENT_PORT environment variables before starting:
    export HOST=0.0.0.0
    export AGENT_PORT=8090
    agentprobe serve

Or use the provided run.sh at the repo root.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentprobe.a2a.adapter import A2ATargetAdapter
from agentprobe.a2a.schemas import (
    A2ATask,
    AgentCapabilities,
    AgentCard,
    AgentProvider,
    AgentSkill,
    Artifact,
    AuthScheme,
    DataPart,
    TaskStatus,
    TextPart,
)
from agentprobe.config import load_config
from agentprobe.report.generator import ReportGenerator
from agentprobe.swarm.orchestrator import AgentProbeOrchestrator

# ---------------------------------------------------------------------------
# A2A 1.0 error codes
# ---------------------------------------------------------------------------
_ERR_TASK_NOT_FOUND = -32501
_ERR_TASK_NOT_CANCELABLE = -32502
_ERR_UNSUPPORTED_OPERATION = -32503
_ERR_INVALID_PARAMS = -32602
_ERR_PARSE_ERROR = -32700


# ---------------------------------------------------------------------------
# Agent Card
# ---------------------------------------------------------------------------

def build_agent_card(base_url: str) -> AgentCard:
    return AgentCard(
        schemaVersion="1.0",
        humanReadableId="agentprobe/security-red-team",
        agentVersion="0.1.0",
        name="AgentProbe",
        description=(
            "Security red-team benchmark for AI agents. "
            "Runs structured adversarial attacks (prompt injection, tool manipulation, "
            "data exfiltration, prompt extraction, reasoning hijack) and returns "
            "OWASP-aligned vulnerability reports with CVSS-like severity scores."
        ),
        url=base_url,
        provider=AgentProvider(
            name="AgentProbe",
            url="https://github.com/your-org/agentprobe",
            support_contact="https://github.com/your-org/agentprobe/issues",
        ),
        capabilities=AgentCapabilities(
            a2aVersion="1.0",
            streaming=False,
            pushNotifications=False,
            stateTransitionHistory=True,
            supportedMessageParts=["text", "data"],
        ),
        authSchemes=[AuthScheme(scheme="none")],
        skills=[
            AgentSkill(
                id="security_red_team",
                name="Security Red-Team Benchmark",
                description=(
                    "Benchmarks an AI agent against OWASP LLM Top 10 attack vectors. "
                    "Provide the competitor agent URL and optional scan settings in a data part."
                ),
                tags=["security", "red-team", "owasp", "llm", "benchmark"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "competitor_agent_url": {
                            "type": "string",
                            "description": "HTTP(S) URL of the A2A competitor agent to benchmark",
                        },
                        "attacks": {
                            "type": "string",
                            "description": "Comma-separated attack families or 'all'",
                            "default": "all",
                        },
                        "recon_messages": {
                            "type": "integer",
                            "description": "Number of recon probe turns (3-5 recommended)",
                            "default": 4,
                        },
                    },
                    "required": ["competitor_agent_url"],
                },
                inputModes=["text", "data"],
                outputModes=["text", "data"],
                examples=[
                    '{"competitor_agent_url": "http://my-agent:8080", "attacks": "all"}',
                    '{"competitor_agent_url": "http://my-agent:8080", "attacks": "prompt_injection,data_exfiltration", "recon_messages": 3}',
                ],
            )
        ],
        tags=["security", "red-team", "benchmark", "owasp", "llm"],
        documentationUrl="https://github.com/your-org/agentprobe#readme",
        lastUpdated=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# ---------------------------------------------------------------------------
# Helpers — extract scan config from incoming A2A message
# ---------------------------------------------------------------------------

def _extract_scan_config(params: dict) -> dict:
    """Pull scan settings out of a SendMessage params dict.

    Priority:
      1. data part  -> {"competitor_agent_url": "...", "attacks": "all", ...}
      2. text part  -> first HTTP/HTTPS URL is used as competitor_agent_url
    """
    message = params.get("message", {})
    parts = message.get("parts", [])

    for part in parts:
        # Accept both "kind" (A2A 1.0) and "type" (legacy)
        part_kind = part.get("kind") or part.get("type")
        if part_kind == "data":
            cfg = part.get("data", {})
            if "competitor_agent_url" in cfg:
                return cfg

    for part in parts:
        part_kind = part.get("kind") or part.get("type")
        if part_kind == "text":
            urls = re.findall(r"https?://\S+", part.get("text", ""))
            if urls:
                return {"competitor_agent_url": urls[0]}

    raise ValueError(
        "competitor_agent_url not found. "
        'Send a data part: {"competitor_agent_url": "http://my-agent:8080"}'
    )


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _run_scan(
    task_id: str,
    scan_config: dict,
    ap_config: dict,
    store: dict,
    lock: threading.Lock,
) -> None:
    """Execute the full AgentProbe scan and update the task store on completion."""
    try:
        with lock:
            if task_id in store:
                store[task_id].status = TaskStatus(state="working")

        competitor_url = scan_config["competitor_agent_url"]
        attacks = scan_config.get("attacks", "all")
        recon_messages = int(scan_config.get("recon_messages", 4))
        payloads_per_attack = scan_config.get("payloads_per_attack")

        cfg = dict(ap_config)
        cfg.setdefault("scan", {})
        cfg["scan"]["recon_messages"] = recon_messages
        if payloads_per_attack is not None:
            cfg["scan"]["payloads_per_attack"] = int(payloads_per_attack)

        adapter = A2ATargetAdapter(competitor_url)
        orchestrator = AgentProbeOrchestrator(target=adapter, config=cfg)
        scan_result = orchestrator.scan(attacks=attacks)

        reporter = ReportGenerator()
        vuln_report = reporter.build_vulnerability_report(scan_result)
        report_json = json.loads(reporter.generate_json(scan_result, vuln_report))

        summary = (
            f"Security benchmark complete. "
            f"{scan_result.successful_attacks}/{scan_result.total_attacks} attacks succeeded "
            f"(success rate: {scan_result.attack_success_rate:.0%}). "
            f"Risk score: {vuln_report.risk_score}/10. "
            f"{len(vuln_report.findings)} exploitable finding(s) confirmed."
        )

        artifact = Artifact(
            name="vulnerability_report",
            description="AgentProbe security benchmark results",
            parts=[
                TextPart(text=summary),
                DataPart(data=report_json),
            ],
        )

        with lock:
            if task_id in store:
                store[task_id].status = TaskStatus(state="completed")
                store[task_id].artifacts = [artifact]

    except Exception as exc:
        with lock:
            if task_id in store:
                store[task_id].status = TaskStatus(state="failed")
                store[task_id].artifacts = [
                    Artifact(parts=[TextPart(text=f"Scan failed: {exc}")])
                ]


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(base_url: str = "http://localhost:8090", config: dict | None = None) -> FastAPI:
    """Create and return the FastAPI application.

    Parameters
    ----------
    base_url:
        The public URL where this server is reachable. Written into the Agent Card.
        Defaults to $HOST/$AGENT_PORT env vars if set.
    config:
        AgentProbe config dict (same shape as agentprobe.yaml). Defaults to
        load_config() which reads agentprobe.yaml / env vars.
    """
    ap_config = config or load_config()
    agent_card = build_agent_card(base_url)

    # In-memory task store (sufficient for a benchmark tool)
    _store: dict[str, A2ATask] = {}
    _lock = threading.Lock()

    app = FastAPI(
        title="AgentProbe",
        description="Security red-team benchmark — A2A 1.0 evaluator agent",
        version="0.1.0",
    )

    # ------------------------------------------------------------------
    # Agent Card endpoints
    # ------------------------------------------------------------------

    @app.get("/.well-known/agent-card.json", response_class=JSONResponse)
    async def get_agent_card() -> dict:
        """A2A 1.0 Agent Card endpoint."""
        return agent_card.model_dump()

    @app.get("/.well-known/agent.json", response_class=JSONResponse)
    async def get_agent_card_legacy() -> dict:
        """Backward-compatible alias for /.well-known/agent-card.json."""
        return agent_card.model_dump()

    # ------------------------------------------------------------------
    # Reset endpoint  (required by AgentBeats controller)
    # ------------------------------------------------------------------

    @app.post("/reset")
    async def reset() -> dict:
        """Clear all task state. Called by AgentBeats before each assessment run."""
        with _lock:
            _store.clear()
        return {"status": "ok", "message": "AgentProbe state reset"}

    # ------------------------------------------------------------------
    # JSON-RPC 2.0 endpoint
    # ------------------------------------------------------------------

    @app.post("/", response_class=JSONResponse)
    async def jsonrpc(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": _ERR_PARSE_ERROR, "message": "Parse error"},
            })

        rpc_id = body.get("id")
        method = body.get("method", "")
        params = body.get("params", {})

        # ---- SendMessage (A2A 1.0) / tasks/send (legacy) ---------------
        if method in ("SendMessage", "tasks/send"):
            try:
                scan_config = _extract_scan_config(params)
            except ValueError as exc:
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rpc_id,
                    "error": {"code": _ERR_INVALID_PARAMS, "message": str(exc)},
                })

            # Resolve task/context IDs
            message = params.get("message", {})
            task_id = message.get("taskId") or params.get("id") or str(uuid.uuid4())
            context_id = message.get("contextId") or params.get("sessionId") or str(uuid.uuid4())

            task = A2ATask(id=task_id, contextId=context_id, sessionId=context_id)

            with _lock:
                _store[task_id] = task

            threading.Thread(
                target=_run_scan,
                args=(task_id, scan_config, ap_config, _store, _lock),
                daemon=True,
            ).start()

            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": task.model_dump(mode="json"),
            })

        # ---- GetTask (A2A 1.0) / tasks/get (legacy) --------------------
        elif method in ("GetTask", "tasks/get"):
            task_id = params.get("id", "")
            with _lock:
                task = _store.get(task_id)
            if task is None:
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rpc_id,
                    "error": {
                        "code": _ERR_TASK_NOT_FOUND,
                        "message": f"Task '{task_id}' not found",
                    },
                })
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": task.model_dump(mode="json"),
            })

        # ---- ListTasks (A2A 1.0) ----------------------------------------
        elif method == "ListTasks":
            with _lock:
                tasks = [t.model_dump(mode="json") for t in _store.values()]
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": {
                    "tasks": tasks,
                    "nextPageToken": "",
                    "pageSize": len(tasks),
                    "totalSize": len(tasks),
                },
            })

        # ---- CancelTask (A2A 1.0) / tasks/cancel (legacy) --------------
        elif method in ("CancelTask", "tasks/cancel"):
            task_id = params.get("id", "")
            with _lock:
                task = _store.get(task_id)
            if task is None:
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rpc_id,
                    "error": {
                        "code": _ERR_TASK_NOT_FOUND,
                        "message": f"Task '{task_id}' not found",
                    },
                })
            terminal = {"completed", "failed", "canceled"}
            if task.status.state in terminal:
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rpc_id,
                    "error": {
                        "code": _ERR_TASK_NOT_CANCELABLE,
                        "message": f"Task '{task_id}' is already in terminal state '{task.status.state}'",
                    },
                })
            with _lock:
                _store[task_id].status = TaskStatus(state="canceled")
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": {"id": task_id, "status": {"state": "canceled"}},
            })

        # ---- unsupported method ----------------------------------------
        else:
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "error": {
                    "code": _ERR_UNSUPPORTED_OPERATION,
                    "message": f"Method not supported: {method}",
                },
            })

    return app
