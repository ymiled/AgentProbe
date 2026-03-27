"""Minimal A2A server wrapping the demo TargetAgent (financial analyst).

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
    agentprobe serve --port 8090              # Scenario B (evaluator server)
"""

import uuid

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentprobe.a2a.schemas import (
    A2ATask,
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    Artifact,
    TaskStatus,
    TextPart,
    DataPart,
)
from agentprobe.config import load_config
from agentprobe.target.financial_agent import TargetAgent

_llm_cfg = load_config().get("llm", {})

# ---------------------------------------------------------------------------
# One shared agent instance (stateful — history kept between turns)
# The A2ATargetAdapter resets session_id between attacks, which maps to
# TargetAgent.reset() here.
# ---------------------------------------------------------------------------
_sessions: dict[str, TargetAgent] = {}


def _get_or_create_agent(session_id: str) -> TargetAgent:
    if session_id not in _sessions:
        _sessions[session_id] = TargetAgent(config=_llm_cfg)
    return _sessions[session_id]


# ---------------------------------------------------------------------------
# Agent Card
# ---------------------------------------------------------------------------
AGENT_CARD = AgentCard(
    name="Demo Financial Analyst",
    description=(
        "Intentionally vulnerable LangGraph financial analyst agent. "
        "Has read_document, query_database, and write_summary tools. "
        "Used as a red-team target for AgentProbe benchmarks."
    ),
    url="http://localhost:8081",
    version="0.1.0",
    capabilities=AgentCapabilities(streaming=False, pushNotifications=False),
    skills=[
        AgentSkill(
            id="financial_analysis",
            name="Financial Document Analysis",
            description="Read documents, query database, produce summaries.",
            tags=["finance", "demo", "vulnerable"],
        )
    ],
)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Demo competitor Agent")


@app.get("/.well-known/agent.json")
async def agent_card() -> dict:
    return AGENT_CARD.model_dump()


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

    if method == "tasks/send":
        task_id = params.get("id") or str(uuid.uuid4())
        session_id = params.get("sessionId") or str(uuid.uuid4())

        # Extract text from the message
        message_obj = params.get("message", {})
        text = ""
        for part in message_obj.get("parts", []):
            if part.get("type") == "text":
                text += part.get("text", "")

        if not text:
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "error": {"code": -32602, "message": "No text content in message"},
            })

        # Invoke the agent
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
            sessionId=session_id,
            status=TaskStatus(state="completed"),
            artifacts=[Artifact(parts=artifact_parts)],
        )
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "result": task.model_dump(mode="json"),
        })

    elif method == "tasks/get":
        # Stateless server — we don't store task history
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": -32001, "message": "Task history not stored in this demo server"},
        })

    else:
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        })


if __name__ == "__main__":
    print("Starting demo competitor agent on http://localhost:8081")
    print("Agent Card: http://localhost:8081/.well-known/agent.json")
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
