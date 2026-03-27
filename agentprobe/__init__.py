"""AgentProbe — red-teaming framework for AI agent systems."""

__version__ = "0.1.0"

from agentprobe.models.schemas import (
    AttackType,
    OWASPCategory,
    Severity,
    AttackOutcome,
    ToolInfo,
    TargetProfile,
    AttackPayload,
    AttackResult,
    ScanResult,
    VulnerabilityFinding,
    VulnerabilityReport,
)
from agentprobe.config import load_config, get_api_key
from agentprobe.evaluation import OWASP_LLM_TOP_10, SeverityBreakdown, SeverityScorer
from agentprobe.report import ReportGenerator
from agentprobe.swarm import (
    AgentProbeOrchestrator,
    AttackAgent,
    EvaluatorAgent,
    ReconAgent,
    ReporterAgent,
)
from agentprobe.a2a import A2ATargetAdapter, A2AClient

__all__ = [
    "__version__",
    # config
    "load_config",
    "get_api_key",
    # evaluation
    "OWASP_LLM_TOP_10",
    "SeverityBreakdown",
    "SeverityScorer",
    # reporting
    "ReportGenerator",
    # swarm
    "ReconAgent",
    "AttackAgent",
    "EvaluatorAgent",
    "ReporterAgent",
    "AgentProbeOrchestrator",
    # a2a
    "A2ATargetAdapter",
    "A2AClient",
    # models
    "AttackType",
    "OWASPCategory",
    "Severity",
    "AttackOutcome",
    "ToolInfo",
    "TargetProfile",
    "AttackPayload",
    "AttackResult",
    "ScanResult",
    "VulnerabilityFinding",
    "VulnerabilityReport",
]
