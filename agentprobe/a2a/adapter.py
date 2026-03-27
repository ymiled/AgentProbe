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
All messages within a single attack share one sessionId so the competitor agent
can maintain conversation context across multi-turn payloads. Calling reset()
issues a new sessionId, giving subsequent attacks a clean slate.
"""

from __future__ import annotations

from agentprobe.a2a.client import A2AClient
from agentprobe.a2a.schemas import AgentCard


class A2ATargetAdapter:
    """Wraps any A2A competitor agent endpoint as an AgentProbe scan target."""

    def __init__(self, agent_url: str, timeout: float = 120.0):
        self.agent_url = agent_url
        self._client = A2AClient(agent_url, timeout=timeout)
        self._session_id = self._client.new_session()
        self._card: AgentCard | None = None

    # ------------------------------------------------------------------
    # SupportsTarget interface
    # ------------------------------------------------------------------

    def invoke(self, message: str) -> dict:
        """Send a message to the competitor agent and return a normalised response dict."""
        task = self._client.send_task(message, session_id=self._session_id)

        response_text = ""
        tool_calls: list[dict] = []

        # Primary source: task artifacts
        for artifact in task.artifacts:
            for part in artifact.parts:
                if hasattr(part, "text"):
                    response_text += part.text
                elif hasattr(part, "data"):
                    # competitor agent may surface tool calls as structured data
                    tc = part.data.get("tool_calls")
                    if isinstance(tc, list):
                        tool_calls.extend(tc)

        # Fallback: status message (some agents embed the reply there)
        if not response_text and task.status.message:
            for part in task.status.message.parts:
                if hasattr(part, "text"):
                    response_text += part.text

        return {"response": response_text, "tool_calls": tool_calls}

    def reset(self) -> None:
        """Start a fresh session so the next attack sees no prior context."""
        self._session_id = self._client.new_session()

    # ------------------------------------------------------------------
    # Optional helpers
    # ------------------------------------------------------------------

    @property
    def agent_card(self) -> AgentCard:
        """Lazily fetch and cache the competitor agent's Agent Card."""
        if self._card is None:
            self._card = self._client.get_agent_card()
        return self._card
