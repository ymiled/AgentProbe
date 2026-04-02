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
a2a_sendMessage    Start a benchmark. Provide the competitor agent URL in a data part:
                   {"competitor_agent_url": "http://...", "attacks": "all", "recon_messages": 4}
                   Returns the task immediately with state="submitted"; the scan
                   runs in a background thread.

a2a_getTask        Poll for task status and results by task ID.
                   Supports optional historyLength param to limit returned history.

a2a_listTasks      Returns tasks with optional contextId/status filtering and pagination.

a2a_cancelTask     Mark a task as canceled (best-effort; running scan is not interrupted).

Legacy PascalCase aliases (SendMessage, GetTask, ListTasks, CancelTask) and
pre-1.0 REST-style names (tasks/send, tasks/get, tasks/cancel) are also
accepted for backward compatibility with older clients.

Task lifecycle
--------------
  submitted -> working -> completed
                       \\-> failed

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

import asyncio
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentprobe.a2a.schemas import (
    A2AMessage,
    A2ATask,
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    Artifact,
    AuthScheme,
    DataPart,
    TERMINAL_STATES,
    TaskStatus,
    TextPart,
)
from agentprobe.config import load_config

# ---------------------------------------------------------------------------
# A2A 1.0 error codes
# ---------------------------------------------------------------------------
_ERR_TASK_NOT_FOUND = -32501
_ERR_TASK_NOT_CANCELABLE = -32502
_ERR_UNSUPPORTED_OPERATION = -32503
_ERR_INVALID_PARAMS = -32602
_ERR_PARSE_ERROR = -32700

# Method name aliases: both A2A 1.0 (a2a_ prefix) and legacy PascalCase / REST names
_METHOD_SEND = {"a2a_sendMessage", "SendMessage", "tasks/send", "message/send"}
_METHOD_GET = {"a2a_getTask", "GetTask", "tasks/get", "message/get"}
_METHOD_LIST = {"a2a_listTasks", "ListTasks", "message/list"}
_METHOD_CANCEL = {"a2a_cancelTask", "CancelTask", "tasks/cancel", "message/cancel"}


# ---------------------------------------------------------------------------
# Agent Card
# ---------------------------------------------------------------------------

def build_agent_card(base_url: str) -> AgentCard:
    return AgentCard(
        version="0.1.0",
        humanReadableId="agentprobe/security-red-team",
        name="AgentProbe",
        description=(
            "Security red-team benchmark for AI agents. "
            "Runs structured adversarial attacks (prompt injection, tool manipulation, "
            "data exfiltration, prompt extraction, reasoning hijack) and returns "
            "OWASP-aligned vulnerability reports with CVSS-like severity scores."
        ),
        url=base_url,
        interfaces=[AgentInterface(protocol="jsonrpc", url=base_url)],
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
            extendedAgentCard=False,
            supportedMessageParts=["text", "data", "file"],
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


def agent_card_spec_dict(card: AgentCard) -> dict:
    """Return a strict A2A 1.0 spec-compliant dict for the agent card.

    Strips internal-only fields (humanReadableId, interfaces, authSchemes,
    securitySchemes, provider.support_contact) and null values so the
    gateway's Pydantic validator (which uses extra='forbid') doesn't reject it.
    """
    skills = []
    for s in card.skills:
        skill: dict = {
            "id": s.id,
            "name": s.name,
            "description": s.description,
        }
        if s.tags:
            skill["tags"] = s.tags
        if s.examples:
            skill["examples"] = s.examples
        if s.inputModes:
            skill["inputModes"] = s.inputModes
        if s.outputModes:
            skill["outputModes"] = s.outputModes
        skills.append(skill)

    d: dict = {
        "name": card.name,
        "description": card.description,
        "url": card.url,
        "version": card.version,
        "capabilities": {
            "streaming": card.capabilities.streaming,
            "pushNotifications": card.capabilities.pushNotifications,
        },
        "defaultInputModes": card.defaultInputModes,
        "defaultOutputModes": card.defaultOutputModes,
        "skills": skills,
    }
    if card.provider:
        provider: dict = {"organization": card.provider.name}
        if card.provider.url:
            provider["url"] = card.provider.url
        d["provider"] = provider
    if card.tags:
        d["tags"] = card.tags
    if card.documentationUrl:
        d["documentationUrl"] = card.documentationUrl
    if card.iconUrl:
        d["iconUrl"] = card.iconUrl
    if card.lastUpdated:
        d["lastUpdated"] = card.lastUpdated
    return d


# ---------------------------------------------------------------------------
# Helpers — extract scan config from incoming A2A message
# ---------------------------------------------------------------------------

def _extract_scan_config(params: dict) -> dict:
    """Pull scan settings out of a SendMessage params dict.

    Priority:
      1. AMBER_HINT_PROXY env var (amber deployment — proxy IS the competitor endpoint)
      2. data part  -> {"competitor_agent_url": "...", "attacks": "all", ...}
      3. text part  -> first HTTP/HTTPS URL is used as competitor_agent_url
      4. env vars   -> PROXY_URL or COMPETITOR_AGENT_URL
    """
    # In amber deployments AMBER_HINT_PROXY is injected and is the proxy that
    # routes directly to the competitor agent — use it first.
    amber_proxy = os.environ.get("AMBER_HINT_PROXY")
    if amber_proxy:
        return {
            "competitor_agent_url": amber_proxy,
            "attacks": os.environ.get("ATTACKS", "all"),
            "recon_messages": int(os.environ.get("RECON_MESSAGES", "1")),
            "payloads_per_attack": int(os.environ.get("PAYLOADS_PER_ATTACK", "1")),
        }

    message = params.get("message", {})
    parts = message.get("parts", [])

    for part in parts:
        # Accept both "kind" (A2A 1.0) and "type" (legacy)
        part_kind = part.get("kind") or part.get("type")
        if part_kind == "data":
            cfg = part.get("data", {})
            # Direct config: {"competitor_agent_url": "..."}
            if "competitor_agent_url" in cfg:
                return cfg
            # AgentBeats gateway format: {"participants": {"agent": "url"}, "config": {...}}
            participants = cfg.get("participants", {})
            agent_url = participants.get("agent") or participants.get("purple1")
            if agent_url:
                result = dict(cfg.get("config", {}))
                result["competitor_agent_url"] = str(agent_url)
                return result

    for part in parts:
        part_kind = part.get("kind") or part.get("type")
        if part_kind == "text":
            # Stop at characters that are never valid unencoded in a URL but
            # commonly appear immediately after URLs embedded in JSON or prose.
            urls = re.findall(r"https?://[^\s\"'>{}\[\](),;]+", part.get("text", ""))
            if urls:
                return {"competitor_agent_url": urls[0]}

    # Fallback: explicit env var overrides
    proxy_url = os.environ.get("PROXY_URL") or os.environ.get("COMPETITOR_AGENT_URL")
    if proxy_url:
        return {
            "competitor_agent_url": proxy_url,
            "attacks": os.environ.get("ATTACKS", "all"),
            "recon_messages": int(os.environ.get("RECON_MESSAGES", "3")),
            "payloads_per_attack": int(os.environ.get("PAYLOADS_PER_ATTACK", "1")),
        }

    raise ValueError(
        "competitor_agent_url not found. "
        'Send a data part: {"competitor_agent_url": "http://my-agent:8080"}'
    )


def _build_user_message(params: dict, context_id: str, task_id: str) -> A2AMessage:
    """Reconstruct the inbound user A2AMessage from raw JSON-RPC params."""
    raw = dict(params.get("message", {}))
    raw.setdefault("role", "user")
    raw["contextId"] = context_id
    raw["taskId"] = task_id
    return A2AMessage.model_validate(raw)


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
    # Heavy imports deferred here so the FastAPI server starts without delay.
    from agentprobe.a2a.adapter import A2ATargetAdapter
    from agentprobe.report.generator import ReportGenerator
    from agentprobe.swarm.orchestrator import AgentProbeOrchestrator

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

        agent_reply = A2AMessage(
            role="agent",
            parts=[TextPart(text=summary)],
            taskId=task_id,
        )

        with lock:
            if task_id in store:
                store[task_id].status = TaskStatus(state="completed")
                store[task_id].artifacts = [artifact]
                store[task_id].history.append(agent_reply)

    except Exception as exc:
        error_text = f"Scan failed: {exc}"
        agent_reply = A2AMessage(
            role="agent",
            parts=[TextPart(text=error_text)],
            taskId=task_id,
        )
        with lock:
            if task_id in store:
                store[task_id].status = TaskStatus(state="failed")
                store[task_id].artifacts = [
                    Artifact(parts=[TextPart(text=error_text)])
                ]
                store[task_id].history.append(agent_reply)


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

    @app.on_event("startup")
    async def _warmup_imports() -> None:
        """Pre-load heavy dependencies in a background thread at server startup.

        The gateway's readiness poll gives us ~85 s before the first real
        request arrives.  Warming imports here means the first scan request
        won't pay the cold-import penalty (~30-60 s) during the HTTP call.
        """
        def _do_warmup() -> None:
            try:
                from agentprobe.a2a.adapter import A2ATargetAdapter        # noqa: F401
                from agentprobe.report.generator import ReportGenerator    # noqa: F401
                from agentprobe.swarm.orchestrator import AgentProbeOrchestrator  # noqa: F401
            except Exception:
                pass  # warmup failure is non-fatal
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, _do_warmup)

    # ------------------------------------------------------------------
    # Agent Card endpoints
    # ------------------------------------------------------------------

    @app.get("/.well-known/agent-card.json", response_class=JSONResponse)
    async def get_agent_card() -> dict:
        """A2A 1.0 Agent Card endpoint."""
        return agent_card_spec_dict(agent_card)

    @app.get("/.well-known/agent.json", response_class=JSONResponse)
    async def get_agent_card_legacy() -> dict:
        """Backward-compatible alias for /.well-known/agent-card.json."""
        return agent_card_spec_dict(agent_card)

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

        # ---- SendMessage -----------------------------------------------
        if method in _METHOD_SEND:
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

            # Record inbound user message in history
            user_msg = _build_user_message(params, context_id, task_id)
            task.history.append(user_msg)

            with _lock:
                _store[task_id] = task

            # Run scan synchronously so the response already contains the
            # final state (completed/failed).  The gateway reads status from
            # the message/send response body — it does not poll afterwards.
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, _run_scan, task_id, scan_config, ap_config, _store, _lock
            )

            with _lock:
                finished_task = _store.get(task_id, task)

            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": finished_task.model_dump(mode="json"),
            })

        # ---- GetTask ---------------------------------------------------
        elif method in _METHOD_GET:
            task_id = params.get("id", "")
            history_length: int | None = params.get("historyLength")

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

            task_dict = task.model_dump(mode="json")
            # Trim history to requested length (most-recent N entries)
            if history_length is not None and history_length >= 0:
                task_dict["history"] = task_dict["history"][-history_length:]

            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": task_dict,
            })

        # ---- ListTasks -------------------------------------------------
        elif method in _METHOD_LIST:
            filter_context: str | None = params.get("contextId")
            filter_status: str | None = params.get("status")
            page_size: int = int(params.get("pageSize") or 50)
            page_token: str = params.get("pageToken") or ""
            history_length: int | None = params.get("historyLength")

            with _lock:
                all_tasks = list(_store.values())

            # Apply filters
            if filter_context:
                all_tasks = [t for t in all_tasks if t.contextId == filter_context]
            if filter_status:
                all_tasks = [t for t in all_tasks if t.status.state == filter_status]

            # Simple offset-based pagination via numeric page token
            offset = int(page_token) if page_token.isdigit() else 0
            page = all_tasks[offset: offset + page_size]
            next_offset = offset + len(page)
            next_token = str(next_offset) if next_offset < len(all_tasks) else ""

            def _task_dict(t: A2ATask) -> dict:
                d = t.model_dump(mode="json")
                if history_length is not None and history_length >= 0:
                    d["history"] = d["history"][-history_length:]
                return d

            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": {
                    "tasks": [_task_dict(t) for t in page],
                    "nextPageToken": next_token,
                    "pageSize": len(page),
                    "totalSize": len(all_tasks),
                },
            })

        # ---- CancelTask ------------------------------------------------
        elif method in _METHOD_CANCEL:
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
                if task.status.state in TERMINAL_STATES:
                    return JSONResponse({
                        "jsonrpc": "2.0", "id": rpc_id,
                        "error": {
                            "code": _ERR_TASK_NOT_CANCELABLE,
                            "message": f"Task '{task_id}' is already in terminal state '{task.status.state}'",
                        },
                    })
                task.status = TaskStatus(state="canceled")
                task_dict = task.model_dump(mode="json")
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": task_dict,
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
