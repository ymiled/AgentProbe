from agentprobe.attacks.base import BaseAttack
from agentprobe.attacks.prompt_injection import PromptInjectionAttack
from agentprobe.attacks.tool_manipulation import ToolManipulationAttack
from agentprobe.attacks.data_exfiltration import DataExfiltrationAttack
from agentprobe.attacks.prompt_extraction import PromptExtractionAttack
from agentprobe.attacks.reasoning_hijack import ReasoningHijackAttack

_REGISTRY: list[BaseAttack] = [
    PromptInjectionAttack(),
    ToolManipulationAttack(),
    DataExfiltrationAttack(),
    PromptExtractionAttack(),
    ReasoningHijackAttack(),
]


def load_all_attacks() -> list[BaseAttack]:
    """Return a fresh list of all registered attack instances."""
    return list(_REGISTRY)


def load_attacks(names: list[str]) -> list[BaseAttack]:
    """Return only the attacks whose attack_type value matches a name in the list."""
    return [a for a in _REGISTRY if a.attack_type.value in names]


__all__ = [
    "BaseAttack",
    "PromptInjectionAttack",
    "ToolManipulationAttack",
    "DataExfiltrationAttack",
    "PromptExtractionAttack",
    "ReasoningHijackAttack",
    "load_all_attacks",
    "load_attacks",
]
