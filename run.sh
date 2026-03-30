#!/usr/bin/env bash
# AgentBeats controller entry point.
# earthshaker sets $HOST and $AGENT_PORT before calling this script.
# Usage: agentbeats run_ctrl  (after pip install earthshaker)

set -e

export HOST="${HOST:-0.0.0.0}"
export AGENT_PORT="${AGENT_PORT:-8090}"

echo "Starting AgentProbe A2A evaluator on ${HOST}:${AGENT_PORT}"
agentprobe serve --host "$HOST" --port "$AGENT_PORT"
