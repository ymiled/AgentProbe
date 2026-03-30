"""agentprobe.a2a — A2A (Agent-to-Agent) protocol support.

evaluator agent (benchmark server)
-------------------------------
    from agentprobe.a2a.server import create_app
    app = create_app(base_url="http://localhost:8090")
    # start with: uvicorn agentprobe.a2a.server:app
    # or via CLI: agentprobe serve

competitor agent adapter (scan an A2A target)
------------------------------------------
    from agentprobe.a2a import A2ATargetAdapter
    from agentprobe import AgentProbeOrchestrator

    adapter = A2ATargetAdapter("http://my-agent:8080")
    result = AgentProbeOrchestrator(target=adapter).scan()
"""

from agentprobe.a2a.adapter import A2ATargetAdapter
from agentprobe.a2a.client import A2AClient
from agentprobe.a2a.schemas import (
    A2AMessage,
    A2ATask,
    AgentCard,
    AgentCapabilities,
    AgentProvider,
    AgentSkill,
    Artifact,
    AuthScheme,
    DataPart,
    Part,
    TaskStatus,
    TextPart,
)

__all__ = [
    # Adapter (competitor agent client)
    "A2ATargetAdapter",
    "A2AClient",
    # Schemas
    "Part",
    "TextPart",
    "DataPart",
    "A2AMessage",
    "TaskStatus",
    "Artifact",
    "A2ATask",
    "AgentCard",
    "AgentCapabilities",
    "AgentProvider",
    "AgentSkill",
    "AuthScheme",
]
