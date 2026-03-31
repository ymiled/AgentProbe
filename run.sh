#!/usr/bin/env bash
# AgentBeats entry point.
# When PROXY_URL is set (injected by amber router), run a direct scan against
# the competitor and exit. Otherwise start the A2A evaluator server.

set -e

export HOST="${HOST:-0.0.0.0}"
export AGENT_PORT="${AGENT_PORT:-8090}"

# Amber injects the competitor's endpoint as PROXY_URL.
# AgentBeats also passes scan config prefixed with "green_".
COMPETITOR_URL="${PROXY_URL:-${GREEN_COMPETITOR_AGENT_URL:-}}"
ATTACKS="${GREEN_ATTACKS:-all}"
RECON_MESSAGES="${GREEN_RECON_MESSAGES:-3}"

if [ -n "$COMPETITOR_URL" ]; then
    echo "AgentBeats mode: scanning $COMPETITOR_URL"
    echo "  attacks=$ATTACKS recon_messages=$RECON_MESSAGES"
    exec agentprobe scan \
        --target-url "$COMPETITOR_URL" \
        --attacks "$ATTACKS" \
        --recon-messages "$RECON_MESSAGES" \
        --fast \
        --output /tmp/agentprobe-output \
        --format json
else
    echo "Starting AgentProbe A2A evaluator on ${HOST}:${AGENT_PORT}"
    exec agentprobe serve --host "$HOST" --port "$AGENT_PORT"
fi
