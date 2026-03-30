"""A2A (Agent-to-Agent) protocol Pydantic models.

Follows the A2A 1.0 specification:
  https://a2a-protocol.org/latest/specification/

Key types
---------
Part          — atomic content unit (text or structured data)
A2AMessage    — a single turn in a task conversation
TaskStatus    — lifecycle state of a task (submitted → working → completed/failed)
Artifact      — output produced by the agent
A2ATask       — the top-level work unit exchanged between agents
AgentCard     — agent identity + capability descriptor (/.well-known/agent-card.json)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Content parts  (A2A 1.0 uses "kind", not "type")
# ---------------------------------------------------------------------------

class TextPart(BaseModel):
    kind: Literal["text"] = "text"
    text: str


class DataPart(BaseModel):
    kind: Literal["data"] = "data"
    data: dict[str, Any]


Part = Annotated[Union[TextPart, DataPart], Field(discriminator="kind")]


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------

class A2AMessage(BaseModel):
    role: Literal["user", "agent"]
    parts: list[Part]
    messageId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    contextId: str | None = None
    taskId: str | None = None


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------

TaskState = Literal[
    "submitted", "working", "completed", "failed",
    "canceled", "input-required", "auth-required",
]


class TaskStatus(BaseModel):
    state: TaskState = "submitted"
    message: A2AMessage | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Artifact(BaseModel):
    artifactId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str | None = None
    description: str | None = None
    parts: list[Part]
    index: int = 0
    lastChunk: bool = True


class A2ATask(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    contextId: str | None = None   # A2A 1.0 — identifies conversation thread
    sessionId: str | None = None   # kept for backward compatibility
    status: TaskStatus = Field(default_factory=TaskStatus)
    artifacts: list[Artifact] = []
    history: list[A2AMessage] = []
    metadata: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Agent Card
# ---------------------------------------------------------------------------

class AgentProvider(BaseModel):
    name: str
    url: str | None = None
    support_contact: str | None = None


class AuthScheme(BaseModel):
    scheme: Literal["apiKey", "oauth2", "bearer", "basic", "none"]
    description: str | None = None
    tokenUrl: str | None = None   # required for oauth2
    scopes: list[str] = []
    service_identifier: str | None = None


class AgentCapabilities(BaseModel):
    a2aVersion: str = "1.0"
    streaming: bool = False
    pushNotifications: bool = False
    stateTransitionHistory: bool = True
    supportedMessageParts: list[str] = ["text", "data"]


class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    tags: list[str] = []
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    inputModes: list[str] = ["text", "data"]
    outputModes: list[str] = ["text", "data"]
    examples: list[str] = []


class AgentCard(BaseModel):
    schemaVersion: str = "1.0"
    humanReadableId: str              # e.g. "myorg/agent-name"
    agentVersion: str                 # semver of this agent build
    name: str
    description: str
    url: str
    provider: AgentProvider
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    authSchemes: list[AuthScheme] = Field(
        default_factory=lambda: [AuthScheme(scheme="none")]
    )
    skills: list[AgentSkill] = []
    defaultInputModes: list[str] = ["text", "data"]
    defaultOutputModes: list[str] = ["text", "data"]
    tags: list[str] = []
    documentationUrl: str | None = None
    lastUpdated: str | None = None
