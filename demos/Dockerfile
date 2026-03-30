# Demo competitor agent — Purple agent
# Runs: python demos/demo_evaluator_agent.py
# Listens on $HOST:$AGENT_PORT (set by AgentBeats controller)

FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
COPY agentprobe/ agentprobe/
COPY demos/ demos/
COPY agentprobe.yaml .

RUN uv pip install --system -e ".[a2a]"

ENV HOST=0.0.0.0
ENV AGENT_PORT=8081

EXPOSE 8081

CMD ["python", "demos/demo_evaluator_agent.py"]
