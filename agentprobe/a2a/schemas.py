"""A2A (Agent-to-Agent) protocol Pydantic models.

Follows the A2A 1.0 specification:
  https://a2a-protocol.org/latest/specification/

Key types
---------
Part          — atomic content unit (text, structured data, or file)
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

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Content parts  (A2A 1.0 uses "kind" discriminator)
# ---------------------------------------------------------------------------

class TextPart(BaseModel):
    kind: Literal["text"] = "text"
    text: str
    metadata: dict[str, Any] = {}


class DataPart(BaseModel):
    kind: Literal["data"] = "data"
    data: dict[str, Any]
    metadata: dict[str, Any] = {}


class FileContent(BaseModel):
    """Inline or referenced file content."""
    mimeType: str | None = None
    # Exactly one of bytes (base64-encoded inline) or uri should be set
    bytes: str | None = None   # base64-encoded binary data
    uri: str | None = None     # reference to external file


class FilePart(BaseModel):
    kind: Literal["file"] = "file"
    file: FileContent
    metadata: dict[str, Any] = {}


Part = Annotated[Union[TextPart, DataPart, FilePart], Field(discriminator="kind")]


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------

class A2AMessage(BaseModel):
    role: Literal["user", "agent"]
    parts: list[Part]
    messageId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    contextId: str | None = None
    taskId: str | None = None
    metadata: dict[str, Any] = {}
    extensions: list[str] = []
    referenceTaskIds: list[str] = []


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------

TaskState = Literal[
    "submitted", "working", "completed", "failed",
    "canceled", "input-required", "auth-required", "rejected",
]

TERMINAL_STATES: frozenset[str] = frozenset(
    {"completed", "failed", "canceled", "rejected"}
)


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
    append: bool = False


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


class AgentInterface(BaseModel):
    """A single protocol binding (endpoint) for an agent."""
    protocol: Literal["jsonrpc", "grpc", "rest"] = "jsonrpc"
    url: str


class SecurityScheme(BaseModel):
    """OpenAPI-aligned security scheme descriptor."""
    type: Literal["apiKey", "http", "oauth2", "openIdConnect", "mtls", "none"]
    description: str | None = None
    # http scheme fields
    scheme: str | None = None          # e.g. "bearer", "basic"
    bearerFormat: str | None = None
    # apiKey fields
    name: str | None = None
    in_: str | None = Field(None, alias="in")
    # oauth2 fields
    tokenUrl: str | None = None
    scopes: dict[str, str] = {}
    # openIdConnect
    openIdConnectUrl: str | None = None

    model_config = ConfigDict(populate_by_name=True)


# Keep AuthScheme as a backward-compatible alias used by existing server code
class AuthScheme(BaseModel):
    scheme: Literal["apiKey", "oauth2", "bearer", "basic", "none"]
    description: str | None = None
    tokenUrl: str | None = None
    scopes: list[str] = []
    service_identifier: str | None = None


class AgentCapabilities(BaseModel):
    a2aVersion: str = "1.0"
    streaming: bool = False
    pushNotifications: bool = False
    stateTransitionHistory: bool = True
    extendedAgentCard: bool = False
    supportedMessageParts: list[str] = ["text", "data", "file"]


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
    url: str                          # primary endpoint URL (convenience, mirrors interfaces[0].url)
    interfaces: list[AgentInterface] = []  # A2A 1.0: supported protocol bindings
    provider: AgentProvider
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    # A2A 1.0: map of scheme-name → SecurityScheme
    securitySchemes: dict[str, SecurityScheme] = {}
    # Backward-compat list used by existing server/client code
    authSchemes: list[AuthScheme] = Field(
        default_factory=lambda: [AuthScheme(scheme="none")]
    )
    skills: list[AgentSkill] = []
    defaultInputModes: list[str] = ["text", "data", "file"]
    defaultOutputModes: list[str] = ["text", "data", "file"]
    tags: list[str] = []
    documentationUrl: str | None = None
    iconUrl: str | None = None
    lastUpdated: str | None = None
