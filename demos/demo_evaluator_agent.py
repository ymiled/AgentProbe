"""Minimal A2A 1.0 server wrapping the demo TargetAgent (financial analyst).

This makes the built-in LangGraph agent reachable over HTTP so it can be
benchmarked by A2ATargetAdapter or a remote AgentProbe evaluator agent server.

Prerequisites
-------------
    uv pip install -e ".[a2a]"
    export ANTHROPIC_API_KEY=sk-ant-...

Run
---
    python demos/demo_evaluator_agent.py
    # listens on http://localhost:8081

Then in another terminal, either:
    python demos/a2a_scan.py               # Scenario A
    agentprobe serve --port 8090           # Scenario B (evaluator server)

AgentBeats / earthshaker
------------------------
Responds to $HOST and $AGENT_PORT environment variables:
    export HOST=0.0.0.0
    export AGENT_PORT=8081
    python demos/demo_evaluator_agent.py
"""

import os
import uuid
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

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
from agentprobe.a2a.server import agent_card_spec_dict
from agentprobe.config import load_config
from agentprobe.target.financial_agent import TargetAgent

_llm_cfg = load_config().get("llm", {})

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("AGENT_PORT", "8081"))
BASE_URL = f"http://{HOST}:{PORT}"

# ---------------------------------------------------------------------------
# Session management — one TargetAgent per contextId/sessionId
# ---------------------------------------------------------------------------
_sessions: dict[str, TargetAgent] = {}


def _get_or_create_agent(session_id: str) -> TargetAgent:
    if session_id not in _sessions:
        _sessions[session_id] = TargetAgent(config=_llm_cfg)
    return _sessions[session_id]


# ---------------------------------------------------------------------------
# Agent Card  (A2A 1.0 — all required fields present)
# ---------------------------------------------------------------------------
AGENT_CARD = AgentCard(
    version="0.1.0",
    humanReadableId="agentprobe/demo-financial-analyst",
    name="Demo Financial Analyst",
    description=(
        "Intentionally vulnerable LangGraph financial analyst agent. "
        "Has read_document, query_database, and write_summary tools. "
        "Used as a red-team target for AgentProbe benchmarks."
    ),
    url=BASE_URL,
    provider=AgentProvider(
        name="AgentProbe",
        url="https://github.com/your-org/agentprobe",
    ),
    capabilities=AgentCapabilities(
        a2aVersion="1.0",
        streaming=False,
        pushNotifications=False,
        stateTransitionHistory=False,
        supportedMessageParts=["text", "data"],
    ),
    authSchemes=[AuthScheme(scheme="none")],
    skills=[
        AgentSkill(
            id="financial_analysis",
            name="Financial Document Analysis",
            description="Read documents, query database, produce summaries.",
            tags=["finance", "demo", "vulnerable"],
            inputModes=["text"],
            outputModes=["text", "data"],
        )
    ],
    tags=["demo", "finance", "vulnerable", "red-team-target"],
    lastUpdated=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Demo Competitor Agent (Financial Analyst)")


@app.get("/.well-known/agent-card.json")
async def agent_card_v1() -> dict:
    """A2A 1.0 Agent Card endpoint."""
    return agent_card_spec_dict(AGENT_CARD)


@app.get("/.well-known/agent.json")
async def agent_card_legacy() -> dict:
    """Backward-compatible alias."""
    return agent_card_spec_dict(AGENT_CARD)


@app.post("/reset")
async def reset() -> dict:
    """Clear all session state. Called by AgentBeats controller before each assessment."""
    _sessions.clear()
    return {"status": "ok", "message": "All sessions cleared"}


@app.post("/")
async def jsonrpc(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        })

    rpc_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    if method in ("a2a_sendMessage", "SendMessage", "tasks/send"):
        message_obj = params.get("message", {})

        # Resolve session/context ID
        session_id = (
            message_obj.get("contextId")
            or params.get("sessionId")
            or str(uuid.uuid4())
        )
        task_id = message_obj.get("taskId") or params.get("id") or str(uuid.uuid4())

        # Extract text from parts (accept both "kind" and "type" fields)
        text = ""
        for part in message_obj.get("parts", []):
            part_kind = part.get("kind") or part.get("type")
            if part_kind == "text":
                text += part.get("text", "")

        if not text:
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "error": {"code": -32602, "message": "No text content in message"},
            })

        try:
            agent = _get_or_create_agent(session_id)
            result = agent.invoke(text)
        except Exception as exc:
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "error": {"code": -32000, "message": f"Agent error: {exc}"},
            })

        artifact_parts = [TextPart(text=result["response"])]
        if result.get("tool_calls"):
            artifact_parts.append(DataPart(data={"tool_calls": result["tool_calls"]}))

        task = A2ATask(
            id=task_id,
            contextId=session_id,
            sessionId=session_id,
            status=TaskStatus(state="completed"),
            artifacts=[Artifact(parts=artifact_parts)],
        )
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "result": task.model_dump(mode="json"),
        })

    elif method in ("a2a_getTask", "GetTask", "tasks/get"):
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": -32503, "message": "Task history not stored in this demo server"},
        })

    else:
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": -32503, "message": f"Method not supported: {method}"},
        })


if __name__ == "__main__":
    print(f"Starting demo competitor agent on http://{HOST}:{PORT}")
    print(f"Agent Card : http://{HOST}:{PORT}/.well-known/agent-card.json")
    print(f"Reset      : POST http://{HOST}:{PORT}/reset")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
