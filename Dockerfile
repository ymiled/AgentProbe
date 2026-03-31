# AgentProbe — Green (evaluator) agent
# Runs: agentprobe serve
# Listens on $HOST:$AGENT_PORT (set by AgentBeats controller)

FROM python:3.11-slim

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml .
COPY agentprobe/ agentprobe/
COPY agentprobe.yaml .
COPY run.sh .

# Install with A2A server extras
RUN uv pip install --system -e ".[a2a]"

# AgentBeats sets these; defaults work for local testing
ENV HOST=0.0.0.0
ENV AGENT_PORT=8090

EXPOSE 8090

CMD ["sh", "run.sh"]
