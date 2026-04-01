#!/usr/bin/env python3
"""Simulate the AgentBeats gateway readiness + assessment flow locally.

Checks both agents against the A2A 1.0 spec exactly as the gateway does,
so you can catch errors before pushing.

Usage (agents already running):
    python scripts/validate_gateway.py

Usage (start agents automatically):
    python scripts/validate_gateway.py --start-agents

Options:
    --green URL    AgentProbe (green) base URL  [default: http://localhost:8090]
    --purple URL   Competitor (purple) base URL [default: http://localhost:8081]
    --start-agents Launch both servers as subprocesses then validate
    --timeout N    Seconds to wait for agents to become ready [default: 30]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from typing import Any

import httpx

# Try to import the official a2a-sdk for strict gateway-identical validation
try:
    from a2a.types import AgentCard as _SDKAgentCard, Task as _SDKTask
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False


def _fail(msg: str) -> None:
    print(f"  FAIL  {msg}")


def _ok(msg: str) -> None:
    print(f"  OK    {msg}")


def _warn(msg: str) -> None:
    print(f"  WARN  {msg}")


# ---------------------------------------------------------------------------
# Agent card validation
# ---------------------------------------------------------------------------

def validate_agent_card(base_url: str, label: str) -> tuple[bool, dict]:
    """Fetch and validate the agent card. Returns (ok, card_dict)."""
    print(f"\n[{label}] Agent Card — {base_url}/.well-known/agent-card.json")
    card: dict[str, Any] = {}
    ok = True

    # 1. HTTP reachability
    for path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
        try:
            r = httpx.get(f"{base_url}{path}", timeout=10.0)
            if r.status_code == 200:
                card = r.json()
                _ok(f"HTTP 200 on {path}")
                break
            else:
                _fail(f"HTTP {r.status_code} on {path}")
        except httpx.ConnectError:
            _fail(f"Connection refused on {path}")
        except httpx.TimeoutException:
            _fail(f"Timeout on {path}")
    else:
        _fail("Could not fetch agent card from either path")
        return False, {}

    # 2. Parse with the official a2a-sdk — same model the gateway uses
    if _SDK_AVAILABLE:
        try:
            _SDKAgentCard.model_validate(card)
            _ok("Official a2a-sdk AgentCard.model_validate() PASSED")
        except Exception as e:
            _fail(f"Official a2a-sdk parse FAILED: {e}")
            ok = False
    else:
        _warn("a2a-sdk not installed — skipping strict SDK parse (run: uv pip install a2a-sdk)")

    # 3. skills non-empty
    skills = card.get("skills", [])
    if skills:
        _ok(f"{len(skills)} skill(s) declared")
    else:
        _warn("skills array is empty — gateway may reject card")

    return ok, card


# ---------------------------------------------------------------------------
# JSON-RPC endpoint validation
# ---------------------------------------------------------------------------

def validate_rpc_endpoint(base_url: str, label: str) -> bool:
    """Send a minimal SendMessage and confirm the endpoint responds."""
    print(f"\n[{label}] JSON-RPC endpoint — POST {base_url}/")
    ok = True

    # Use SDK-format message (same as gateway sends)
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "role": "user",
                "parts": [{"kind": "text", "text": "ping", "metadata": None}],
                "messageId": str(uuid.uuid4()),
                "contextId": None,
                "taskId": None,
                "metadata": None,
                "extensions": None,
                "referenceTaskIds": None,
            }
        },
    }
    try:
        r = httpx.post(base_url, json=payload, timeout=15.0)
        body = r.json()
        if "result" in body:
            state = body["result"].get("status", {}).get("state", "?")
            _ok(f"Accepted SendMessage — task state: {state}")
            # Validate the Task response parses with the SDK
            if _SDK_AVAILABLE:
                try:
                    _SDKTask.model_validate(body["result"])
                    _ok("Task response parses with a2a-sdk PASSED")
                except Exception as e:
                    _fail(f"Task response SDK parse FAILED: {e}")
                    ok = False
        elif "error" in body:
            code = body["error"].get("code")
            msg = body["error"].get("message", "")
            if code == -32602:
                _ok(f"Endpoint reachable; expected error -32602: {msg}")
            else:
                _warn(f"RPC error {code}: {msg}")
        else:
            _warn(f"Unexpected response shape: {body}")
    except httpx.ConnectError:
        _fail("Connection refused on POST /")
        ok = False
    except Exception as e:
        _fail(f"RPC call failed: {e}")
        ok = False

    return ok


# ---------------------------------------------------------------------------
# Reset endpoint validation
# ---------------------------------------------------------------------------

def validate_reset(base_url: str, label: str) -> bool:
    """Check the /reset endpoint (required by AgentBeats controller)."""
    print(f"\n[{label}] Reset endpoint — POST {base_url}/reset")
    try:
        r = httpx.post(f"{base_url}/reset", timeout=10.0)
        if r.status_code == 200:
            _ok(f"HTTP 200 — {r.json()}")
            return True
        else:
            _fail(f"HTTP {r.status_code}")
            return False
    except Exception as e:
        _fail(f"{e}")
        return False


# ---------------------------------------------------------------------------
# Wait for agent to become ready
# ---------------------------------------------------------------------------

def wait_for_agent(base_url: str, label: str, timeout: int = 30) -> bool:
    print(f"Waiting for {label} at {base_url} (up to {timeout}s)...", end="", flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base_url}/.well-known/agent-card.json", timeout=2.0)
            if r.status_code == 200:
                elapsed = timeout - (deadline - time.monotonic())
                print(f" ready in {elapsed:.1f}s")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(1)
    print(" TIMEOUT")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--green", default="http://localhost:8090", metavar="URL")
    parser.add_argument("--purple", default="http://localhost:8081", metavar="URL")
    parser.add_argument("--start-agents", action="store_true",
                        help="Launch both agents as subprocesses before validating")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    procs: list[subprocess.Popen] = []

    if args.start_agents:
        print("Starting green agent (agentprobe serve)...")
        procs.append(subprocess.Popen(
            ["agentprobe", "serve", "--host", "0.0.0.0", "--port", "8090"],
            env={**__import__("os").environ, "AGENT_PORT": "8090"},
        ))
        print("Starting purple agent (demo_evaluator_agent.py)...")
        procs.append(subprocess.Popen(
            [sys.executable, "demos/demo_evaluator_agent.py"],
            env={**__import__("os").environ, "AGENT_PORT": "8081"},
        ))

    agents = [
        (args.green, "GREEN  agentprobe"),
        (args.purple, "PURPLE competitor"),
    ]

    passed = 0
    total = 0

    try:
        # Wait phase
        for url, label in agents:
            if not wait_for_agent(url, label, args.timeout):
                print(f"\nERROR: {label} never became reachable. Aborting.")
                sys.exit(1)

        # Validation phase
        print("\n" + "=" * 60)
        print("GATEWAY SIMULATION — A2A 1.0 Readiness Checks")
        print("=" * 60)

        all_ok = True
        for url, label in agents:
            card_ok, card = validate_agent_card(url, label)
            rpc_ok = validate_rpc_endpoint(url, label)
            reset_ok = validate_reset(url, label)
            agent_ok = card_ok and rpc_ok and reset_ok
            total += 1
            if agent_ok:
                passed += 1
                print(f"\n  [{label}] READY")
            else:
                print(f"\n  [{label}] NOT READY")
            all_ok = all_ok and agent_ok

        print("\n" + "=" * 60)
        print(f"Result: {passed}/{total} agents ready")
        if all_ok:
            print("Both agents PASS — safe to submit on AgentBeats.")
        else:
            print("Fix the FAIL items above before submitting.")
            sys.exit(1)

    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
