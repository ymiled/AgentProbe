"""Synchronous A2A 1.0 HTTP client.

Used by A2ATargetAdapter to send tasks to a competitor agent endpoint.
Implements the JSON-RPC 2.0 binding of the A2A 1.0 spec.
"""

from __future__ import annotations

import uuid

import httpx

from agentprobe.a2a.schemas import A2ATask, AgentCard


class A2AClient:
    """Minimal synchronous JSON-RPC client for A2A 1.0 task communication."""

    def __init__(self, base_url: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Agent Card discovery
    # ------------------------------------------------------------------

    def get_agent_card(self) -> AgentCard:
        """Fetch the agent's identity and capability descriptor.

        Tries /.well-known/agent-card.json (A2A 1.0) first, falls back to
        /.well-known/agent.json for older deployments.
        """
        with httpx.Client(timeout=self.timeout) as http:
            for path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
                try:
                    r = http.get(f"{self.base_url}{path}")
                    if r.status_code == 200:
                        return AgentCard.model_validate(r.json())
                except httpx.HTTPError:
                    continue
        raise RuntimeError(
            f"Could not fetch Agent Card from {self.base_url} "
            "(tried /.well-known/agent-card.json and /.well-known/agent.json)"
        )

    # ------------------------------------------------------------------
    # Task operations  (A2A 1.0 JSON-RPC method names)
    # ------------------------------------------------------------------

    def send_task(
        self,
        message: str,
        session_id: str | None = None,
        task_id: str | None = None,
    ) -> A2ATask:
        """Send a user message as an A2A task and return the result.

        Uses the A2A 1.0 method name ``SendMessage``.  For agents that return
        ``working`` status the caller should poll with ``get_task``.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": message}],
                    "messageId": str(uuid.uuid4()),
                    "contextId": session_id,
                },
                "configuration": {
                    "acceptedOutputModes": ["text", "data"],
                },
            },
        }
        if task_id:
            payload["params"]["message"]["taskId"] = task_id

        with httpx.Client(timeout=self.timeout) as http:
            r = http.post(self.base_url, json=payload)
            r.raise_for_status()

        body = r.json()
        if "error" in body:
            raise RuntimeError(
                f"A2A SendMessage error from {self.base_url}: {body['error']}"
            )
        return A2ATask.model_validate(body["result"])

    def get_task(self, task_id: str) -> A2ATask:
        """Poll for the current state of a task (A2A 1.0: GetTask)."""
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "GetTask",
            "params": {"id": task_id},
        }
        with httpx.Client(timeout=self.timeout) as http:
            r = http.post(self.base_url, json=payload)
            r.raise_for_status()

        body = r.json()
        if "error" in body:
            raise RuntimeError(f"GetTask error: {body['error']}")
        return A2ATask.model_validate(body["result"])

    def reset_agent(self) -> bool:
        """Call the /reset endpoint if supported (AgentBeats controller requirement)."""
        try:
            with httpx.Client(timeout=30.0) as http:
                r = http.post(f"{self.base_url}/reset")
                return r.status_code == 200
        except httpx.HTTPError:
            return False

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    @staticmethod
    def new_session() -> str:
        """Generate a fresh context/session ID to isolate a conversation."""
        return str(uuid.uuid4())
