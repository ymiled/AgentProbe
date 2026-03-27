"""A2A (Agent-to-Agent) protocol Pydantic models.

Follows the A2A specification:
  https://a2a-protocol.org/latest/specification/

Key types
---------
Part          — atomic content unit (text or structured data)
A2AMessage    — a single turn in a task conversation
TaskStatus    — lifecycle state of a task (submitted → working → completed/failed)
Artifact      — output produced by the agent
A2ATask       — the top-level work unit exchanged between agents
AgentCard     — agent identity + capability descriptor (/.well-known/agent.json)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Content parts
# ---------------------------------------------------------------------------

class TextPart(BaseModel):
    type: Literal["text"] = "text"
    text: str


class DataPart(BaseModel):
    type: Literal["data"] = "data"
    data: dict[str, Any]


Part = Annotated[Union[TextPart, DataPart], Field(discriminator="type")]


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------

class A2AMessage(BaseModel):
    role: Literal["user", "agent"]
    parts: list[Part]


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------

class TaskStatus(BaseModel):
    state: Literal["submitted", "working", "completed", "failed", "canceled"]
    message: A2AMessage | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Artifact(BaseModel):
    name: str | None = None
    description: str | None = None
    parts: list[Part]
    index: int = 0
    lastChunk: bool = True


class A2ATask(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sessionId: str | None = None
    status: TaskStatus = Field(
        default_factory=lambda: TaskStatus(state="submitted")
    )
    artifacts: list[Artifact] = []
    history: list[A2AMessage] = []
    metadata: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Agent Card
# ---------------------------------------------------------------------------

class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    tags: list[str] = []
    inputModes: list[str] = ["text", "data"]
    outputModes: list[str] = ["text", "data"]
    examples: list[str] = []


class AgentCapabilities(BaseModel):
    streaming: bool = False
    pushNotifications: bool = False
    stateTransitionHistory: bool = True


class AgentCard(BaseModel):
    name: str
    description: str
    url: str
    version: str
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    skills: list[AgentSkill]
    defaultInputModes: list[str] = ["text", "data"]
    defaultOutputModes: list[str] = ["text", "data"]
