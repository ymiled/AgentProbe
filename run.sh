#!/usr/bin/env bash
# AgentBeats controller entry point.
# The gateway sends the competitor URL inside the A2A message (participants["agent"]).
# AMBER_HINT_PROXY is set in amber.json so amber permits outbound connections.

set -e

export HOST="${HOST:-0.0.0.0}"
export AGENT_PORT="${AGENT_PORT:-8090}"

echo "Starting AgentProbe A2A evaluator on ${HOST}:${AGENT_PORT}"
exec agentprobe serve --host "$HOST" --port "$AGENT_PORT"
