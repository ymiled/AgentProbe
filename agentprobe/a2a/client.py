"""Synchronous A2A 1.0 HTTP client.

Used by A2ATargetAdapter to send tasks to a competitor agent endpoint.
Implements the JSON-RPC 2.0 binding of the A2A 1.0 spec.

Method names follow the A2A 1.0 convention (a2a_ prefix) with automatic
fallback to legacy PascalCase names for older servers.
"""

from __future__ import annotations

import time
import uuid

import httpx

from agentprobe.a2a.schemas import TERMINAL_STATES, A2ATask, AgentCard


class A2AClient:
    """Synchronous JSON-RPC client for A2A 1.0 task communication."""

    # Delay between polling attempts when a task is in working state
    _POLL_INTERVAL: float = 1.5
    # Maximum total seconds to wait for a task to reach a terminal state
    _POLL_TIMEOUT: float = 300.0

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
    # Task operations  (A2A 1.0 JSON-RPC method names with legacy fallback)
    # ------------------------------------------------------------------

    def _rpc(self, http: httpx.Client, method: str, params: dict) -> dict:
        """Send one JSON-RPC 2.0 request and return the parsed body.

        Tries the A2A 1.0 ``a2a_`` prefixed method name first; falls back to
        the legacy PascalCase name if the server returns -32601 (method not
        found) so that older A2A servers remain compatible.
        """
        legacy = {
            "a2a_sendMessage": "SendMessage",
            "a2a_getTask": "GetTask",
            "a2a_listTasks": "ListTasks",
            "a2a_cancelTask": "CancelTask",
        }
        for attempt_method in (method, legacy.get(method)):
            if attempt_method is None:
                break
            payload = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": attempt_method,
                "params": params,
            }
            r = http.post(self.base_url, json=payload)
            r.raise_for_status()
            body = r.json()
            # -32601 = method not found — try legacy name
            if "error" in body and body["error"].get("code") == -32601:
                continue
            return body
        return body  # return last response even if both failed

    def send_task(
        self,
        message: str,
        session_id: str | None = None,
        task_id: str | None = None,
    ) -> A2ATask:
        """Send a user message as an A2A task and poll until it reaches a terminal state.

        Uses the A2A 1.0 method ``a2a_sendMessage`` (falls back to ``SendMessage``).
        Polls with ``a2a_getTask`` when the initial response is ``working`` or
        ``submitted`` so callers always receive a fully-resolved task.
        """
        params: dict = {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": message}],
                "messageId": str(uuid.uuid4()),
                "contextId": session_id,
            },
            "configuration": {
                "acceptedOutputModes": ["text", "data", "file"],
            },
        }
        if task_id:
            params["message"]["taskId"] = task_id

        with httpx.Client(timeout=self.timeout) as http:
            body = self._rpc(http, "a2a_sendMessage", params)

        if "error" in body:
            raise RuntimeError(
                f"A2A SendMessage error from {self.base_url}: {body['error']}"
            )

        task = A2ATask.model_validate(body["result"])

        # Poll until the task reaches a terminal state
        if task.status.state not in TERMINAL_STATES:
            task = self._poll_until_done(task.id)

        return task

    def _poll_until_done(self, task_id: str) -> A2ATask:
        """Poll get_task until the task reaches a terminal state or times out."""
        deadline = time.monotonic() + self._POLL_TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(self._POLL_INTERVAL)
            task = self.get_task(task_id)
            if task.status.state in TERMINAL_STATES:
                return task
        # Return last known state even if timed out rather than raising
        return task

    def get_task(self, task_id: str, history_length: int | None = None) -> A2ATask:
        """Poll for the current state of a task (A2A 1.0: a2a_getTask)."""
        params: dict = {"id": task_id}
        if history_length is not None:
            params["historyLength"] = history_length

        with httpx.Client(timeout=self.timeout) as http:
            body = self._rpc(http, "a2a_getTask", params)

        if "error" in body:
            raise RuntimeError(f"GetTask error: {body['error']}")
        return A2ATask.model_validate(body["result"])

    def list_tasks(
        self,
        context_id: str | None = None,
        status: str | None = None,
        page_size: int | None = None,
        page_token: str | None = None,
    ) -> dict:
        """List tasks with optional filtering (A2A 1.0: a2a_listTasks).

        Returns the raw result dict with keys: tasks, nextPageToken, pageSize, totalSize.
        """
        params: dict = {}
        if context_id is not None:
            params["contextId"] = context_id
        if status is not None:
            params["status"] = status
        if page_size is not None:
            params["pageSize"] = page_size
        if page_token is not None:
            params["pageToken"] = page_token

        with httpx.Client(timeout=self.timeout) as http:
            body = self._rpc(http, "a2a_listTasks", params)

        if "error" in body:
            raise RuntimeError(f"ListTasks error: {body['error']}")
        return body["result"]

    def cancel_task(self, task_id: str) -> A2ATask:
        """Cancel a task by ID (A2A 1.0: a2a_cancelTask)."""
        params = {"id": task_id}

        with httpx.Client(timeout=self.timeout) as http:
            body = self._rpc(http, "a2a_cancelTask", params)

        if "error" in body:
            raise RuntimeError(f"CancelTask error: {body['error']}")
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
