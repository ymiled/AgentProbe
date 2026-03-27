"""Synchronous A2A HTTP client.

Used by A2ATargetAdapter to send tasks to a competitor agent endpoint.
"""

from __future__ import annotations

import uuid

import httpx

from agentprobe.a2a.schemas import A2ATask, AgentCard


class A2AClient:
    """Minimal synchronous JSON-RPC client for A2A task communication."""

    def __init__(self, base_url: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Agent Card discovery
    # ------------------------------------------------------------------

    def get_agent_card(self) -> AgentCard:
        """Fetch the agent's identity and capability descriptor."""
        with httpx.Client(timeout=self.timeout) as http:
            r = http.get(f"{self.base_url}/.well-known/agent.json")
            r.raise_for_status()
        return AgentCard.model_validate(r.json())

    # ------------------------------------------------------------------
    # Task operations
    # ------------------------------------------------------------------

    def send_task(
        self,
        message: str,
        session_id: str | None = None,
        task_id: str | None = None,
    ) -> A2ATask:
        """Send a user message as an A2A task and return the result.

        The competitor agent is expected to process the task synchronously and
        return a completed task. For agents that return `working` status,
        callers should poll with `get_task`.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tasks/send",
            "params": {
                "id": task_id or str(uuid.uuid4()),
                "sessionId": session_id,
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": message}],
                },
            },
        }
        with httpx.Client(timeout=self.timeout) as http:
            r = http.post(self.base_url, json=payload)
            r.raise_for_status()

        body = r.json()
        if "error" in body:
            raise RuntimeError(f"A2A error from agent at {self.base_url}: {body['error']}")
        return A2ATask.model_validate(body["result"])

    def get_task(self, task_id: str) -> A2ATask:
        """Poll for the current state of a task."""
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tasks/get",
            "params": {"id": task_id},
        }
        with httpx.Client(timeout=self.timeout) as http:
            r = http.post(self.base_url, json=payload)
            r.raise_for_status()

        body = r.json()
        if "error" in body:
            raise RuntimeError(f"tasks/get error: {body['error']}")
        return A2ATask.model_validate(body["result"])

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    @staticmethod 
    def new_session() -> str:
        """Generate a fresh session ID to isolate a conversation."""
        return str(uuid.uuid4())
