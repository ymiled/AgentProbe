from agentprobe.models.schemas import AttackType, OWASPCategory


OWASP_LLM_TOP_10: dict[str, dict] = {
    OWASPCategory.LLM01.value: {
        "title": "Prompt Injection",
        "cwes": ["CWE-74", "CWE-77", "CWE-116"],
        "attack_types": [
            AttackType.PROMPT_INJECTION.value,
            AttackType.REASONING_HIJACK.value,
        ],
        "description": "Untrusted input manipulates model behavior and tool execution.",
        "remediation": "Treat all tool/document output as untrusted, enforce instruction hierarchy, and apply allow-list task constraints.",
    },
    OWASPCategory.LLM02.value: {
        "title": "Insecure Output Handling",
        "cwes": ["CWE-20", "CWE-79", "CWE-116"],
        "attack_types": [],
        "description": "Unsafe handling of model output by downstream systems or tools.",
        "remediation": "Validate and sanitize model outputs before execution, rendering, or storage.",
    },
    OWASPCategory.LLM06.value: {
        "title": "Sensitive Information Disclosure",
        "cwes": ["CWE-200", "CWE-201", "CWE-359"],
        "attack_types": [
            AttackType.DATA_EXFILTRATION.value,
            AttackType.PROMPT_EXTRACTION.value,
        ],
        "description": "Model discloses secrets, PII, internal prompts, or restricted data.",
        "remediation": "Add PII/secret redaction, data minimization, and strict policy checks before returning responses.",
    },
    OWASPCategory.LLM07.value: {
        "title": "Insecure Plugin Design",
        "cwes": ["CWE-89", "CWE-943", "CWE-285"],
        "attack_types": [AttackType.TOOL_MANIPULATION.value],
        "description": "Unsafe tool interfaces allow abusive or unauthorized actions.",
        "remediation": "Enforce input validation, parameterized DB queries, and least-privilege tool permissions.",
    },
    OWASPCategory.LLM09.value: {
        "title": "Overreliance",
        "cwes": ["CWE-345", "CWE-754", "CWE-693"],
        "attack_types": [AttackType.REASONING_HIJACK.value],
        "description": "System over-trusts model decisions without adequate controls.",
        "remediation": "Require policy gating and verification checks before executing high-risk or context-shifting instructions.",
    },
}


def get_owasp_entry(category: OWASPCategory | str) -> dict:
    """Return OWASP metadata for a category, or a safe fallback entry."""
    key = category.value if isinstance(category, OWASPCategory) else str(category)
    return OWASP_LLM_TOP_10.get(
        key,
        {
            "title": key,
            "cwes": [],
            "attack_types": [],
            "description": "No OWASP metadata found for this category.",
            "remediation": "Review and map this finding to a known OWASP LLM risk category.",
        },
    )


def categories_for_attack_type(attack_type: AttackType | str) -> list[str]:
    """Return all OWASP categories that list the provided attack type."""
    attack_type_value = attack_type.value if isinstance(attack_type, AttackType) else str(attack_type)
    return [
        category
        for category, meta in OWASP_LLM_TOP_10.items()
        if attack_type_value in meta.get("attack_types", [])
    ]
