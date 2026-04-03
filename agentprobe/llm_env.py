"""Normalize LLM-related environment variables for AgentBeats / Docker / local runs."""

from __future__ import annotations

import os


def normalize_gemini_env() -> None:
    """Mirror the API key between GOOGLE_API_KEY and GEMINI_API_KEY.

    LangChain's ChatGoogleGenerativeAI and Google's ``google-genai`` client accept
    either variable; Amber quick-submit and some hosts only inject one name.
    """
    g = (os.environ.get("GOOGLE_API_KEY") or "").strip()
    m = (os.environ.get("GEMINI_API_KEY") or "").strip()
    primary = g or m
    if not primary:
        return
    if not g:
        os.environ["GOOGLE_API_KEY"] = primary
    if not m:
        os.environ["GEMINI_API_KEY"] = primary


def resolve_google_api_key(api_key_env: str | None = None) -> str:
    """Return a non-empty Gemini developer API key, or ''."""
    normalize_gemini_env()
    name = (api_key_env or os.environ.get("AGENTPROBE_LLM_API_KEY_ENV") or "GOOGLE_API_KEY").strip()
    return (
        (os.environ.get(name) or "").strip()
        or (os.environ.get("GOOGLE_API_KEY") or "").strip()
        or (os.environ.get("GEMINI_API_KEY") or "").strip()
    )
