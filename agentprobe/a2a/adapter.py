"""A2ATargetAdapter — bridges an A2A competitor agent to AgentProbe's SupportsTarget protocol.

Any A2A-compliant agent can be red-teamed by passing its URL here:

    adapter = A2ATargetAdapter("http://my-agent:8080")
    orchestrator = AgentProbeOrchestrator(target=adapter)
    result = orchestrator.scan()

Protocol contract (SupportsTarget):
    invoke(message: str) -> {"response": str, "tool_calls": list[dict]}
    reset() -> None

Session handling
----------------
All messages within a single attack share one contextId so the competitor agent
can maintain conversation context across multi-turn payloads. Calling reset()
issues a new contextId *and* calls /reset on the competitor agent (if supported),
giving subsequent attacks a clean slate.

Polling
-------
A2A tasks may be asynchronous. The client polls until the task reaches a
terminal state (completed/failed/canceled/rejected) before returning, so
invoke() always delivers a fully-resolved response regardless of whether the
target agent processes requests synchronously or asynchronously.
"""

from __future__ import annotations

import base64

from agentprobe.a2a.client import A2AClient
from agentprobe.a2a.schemas import AgentCard


class A2ATargetAdapter:
    """Wraps any A2A 1.0 competitor agent endpoint as an AgentProbe scan target."""

    def __init__(self, agent_url: str, timeout: float = 120.0):
        self.agent_url = agent_url
        self._client = A2AClient(agent_url, timeout=timeout)
        self._session_id = self._client.new_session()
        self._card: AgentCard | None = None

    # ------------------------------------------------------------------
    # SupportsTarget interface
    # ------------------------------------------------------------------

    def invoke(self, message: str) -> dict:
        """Send a message to the competitor agent and return a normalised response dict.

        Blocks until the task reaches a terminal state (the client polls
        internally when the task comes back as submitted/working).
        """
        task = self._client.send_task(message, session_id=self._session_id)

        response_text = ""
        tool_calls: list[dict] = []

        for artifact in task.artifacts:
            for part in artifact.parts:
                if hasattr(part, "text"):
                    response_text += part.text
                elif hasattr(part, "data"):
                    tc = part.data.get("tool_calls")
                    if isinstance(tc, list):
                        tool_calls.extend(tc)
                elif hasattr(part, "file"):
                    response_text += self._decode_file_part(part.file)

        # Fallback: status message (some agents embed the reply there)
        if not response_text and task.status.message:
            for part in task.status.message.parts:
                if hasattr(part, "text"):
                    response_text += part.text
                elif hasattr(part, "file"):
                    response_text += self._decode_file_part(part.file)

        return {"response": response_text, "tool_calls": tool_calls}

    @staticmethod
    def _decode_file_part(fc) -> str:
        """Decode a FileContent value to a string for use as response text."""
        if fc.bytes:
            try:
                return base64.b64decode(fc.bytes).decode("utf-8", errors="replace")
            except Exception:
                return ""
        if fc.uri:
            return f"[file: {fc.uri}]"
        return ""

    def reset(self) -> None:
        """Start a fresh session so the next attack sees no prior context.

        Also calls /reset on the competitor agent if supported (AgentBeats requirement).
        """
        self._session_id = self._client.new_session()
        self._client.reset_agent()  # no-op if not supported

    # ------------------------------------------------------------------
    # Optional helpers
    # ------------------------------------------------------------------

    @property
    def agent_card(self) -> AgentCard:
        """Lazily fetch and cache the competitor agent's Agent Card."""
        if self._card is None:
            self._card = self._client.get_agent_card()
        return self._card
