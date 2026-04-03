#!/usr/bin/env bash
# AgentBeats controller entry point.
# The gateway sends the competitor URL inside the A2A message (participants["agent"]).
# AMBER_HINT_PROXY is set in amber.json so amber permits outbound connections.

set -e

export HOST="${HOST:-0.0.0.0}"
export AGENT_PORT="${AGENT_PORT:-8090}"

# google-genai / LangChain accept GOOGLE_API_KEY or GEMINI_API_KEY; keep both in sync.
if [ -n "${GOOGLE_API_KEY:-}" ] && [ -z "${GEMINI_API_KEY:-}" ]; then
  export GEMINI_API_KEY="${GOOGLE_API_KEY}"
fi
if [ -n "${GEMINI_API_KEY:-}" ] && [ -z "${GOOGLE_API_KEY:-}" ]; then
  export GOOGLE_API_KEY="${GEMINI_API_KEY}"
fi

echo "Starting AgentProbe A2A evaluator on ${HOST}:${AGENT_PORT}"
exec agentprobe serve --host "$HOST" --port "$AGENT_PORT"
