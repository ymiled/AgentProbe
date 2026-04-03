from __future__ import annotations

import concurrent.futures
import threading
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any
from typing import Protocol

from agentprobe.config import DEFAULT_CONFIG
from agentprobe.models.schemas import AttackOutcome, AttackPayload, AttackResult, ScanResult
from agentprobe.swarm.attack_agent import AttackAgent
from agentprobe.swarm.evaluator_agent import EvaluatorAgent
from agentprobe.swarm.recon_agent import ReconAgent
from agentprobe.swarm.reporter_agent import ReporterAgent
from agentprobe.target.financial_agent import TargetAgent


class SupportsTarget(Protocol):
    def invoke(self, message: str) -> dict:
        ...

    def reset(self) -> None:
        ...


class AgentProbeOrchestrator:
    """Coordinate recon -> attack -> evaluation -> reporting for a target agent."""

    def __init__(
        self,
        target: SupportsTarget | None = None,
        config: dict[str, Any] | None = None,
        callback: Callable[[dict], None] | None = None,
        target_factory: Callable[[], SupportsTarget] | None = None,
    ):
        self.config = self._merge_with_defaults(config or {})
        self.callback = callback
        self._emit_lock = threading.Lock()

        self.recon_agent = ReconAgent()
        self.attack_agent = AttackAgent()
        self.evaluator_agent = EvaluatorAgent()
        self.reporter_agent = ReporterAgent()

        self.target = target or self._build_default_target(self.config)

        # Resolve the factory used by swarm workers to obtain isolated target instances.
        # Priority: explicit factory > default target (create fresh per worker) > custom target
        # (no factory → swarm mode falls back to sequential with a warning).
        if target_factory is not None:
            self._target_factory: Callable[[], SupportsTarget] | None = target_factory
        elif target is None:
            # Default TargetAgent — safe to construct fresh instances per worker.
            cfg = self.config
            self._target_factory = lambda: self._build_default_target(cfg)
        else:
            # Custom target provided without a factory: cannot guarantee thread safety.
            # Swarm mode will warn and fall back to sequential.
            self._target_factory = None

    def scan(
        self,
        attacks: list[str] | str | None = None,
        mode: str | None = None,
    ) -> ScanResult:
        """Run the full pipeline and return ScanResult."""
        scan_start = time.time()
        mode = mode or self.config["scan"].get("mode", "sequential")

        self._emit("scan_started", mode=mode)

        attack_filter = attacks if attacks is not None else self.config["scan"].get("attacks", "all")
        reset_between = bool(self.config["target"].get("reset_between_attacks", True))
        recon_messages = int(self.config["scan"].get("recon_messages", 4))
        adaptive_retries = bool(self.config["scan"].get("adaptive_retries", True))
        payload_cap = self.config["scan"].get("payloads_per_attack")
        max_payloads_per_attack = int(payload_cap) if payload_cap is not None else None

        target_profile = self.recon_agent.probe_target(self.target, num_messages=recon_messages)
        self._emit(
            "recon_complete",
            tools=[t.name for t in target_profile.tools],
            data_sources=target_profile.data_sources,
        )

        plan = self.attack_agent.build_attack_plan(
            target_profile,
            attack_names=attack_filter,
            max_payloads_per_attack=max_payloads_per_attack,
        )
        self._emit("attack_plan_ready", total_payloads=len(plan))

        if mode == "swarm":
            if self._target_factory is None:
                self._emit(
                    "swarm_fallback",
                    message=(
                        "Swarm mode requires a target_factory when using a custom target. "
                        "Falling back to sequential."
                    ),
                )
                attack_results = self._sequential_scan(plan, reset_between, adaptive_retries)
            else:
                max_workers = int(self.config["scan"].get("max_workers", 8))
                attack_results = self._swarm_scan(plan, reset_between, adaptive_retries, max_workers)
        else:
            attack_results = self._sequential_scan(plan, reset_between, adaptive_retries)

        total_attacks = len(attack_results)
        successful_attacks = sum(1 for r in attack_results if r.outcome in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL})
        blocked_attacks = sum(1 for r in attack_results if r.outcome == AttackOutcome.BLOCKED)

        attack_success_rate = (successful_attacks / total_attacks) if total_attacks else 0.0
        attack_success_rate_with_defense = attack_success_rate

        owasp_coverage: dict[str, int] = {}
        for result in attack_results:
            key = result.owasp_category.value
            owasp_coverage[key] = owasp_coverage.get(key, 0) + 1

        scan_result = ScanResult(
            target_profile=target_profile,
            attack_results=attack_results,
            total_attacks=total_attacks,
            successful_attacks=successful_attacks,
            blocked_attacks=blocked_attacks,
            attack_success_rate=round(attack_success_rate, 4),
            attack_success_rate_with_defense=round(attack_success_rate_with_defense, 4),
            classifier_metrics=None,
            owasp_coverage=owasp_coverage,
            scan_duration_seconds=round(time.time() - scan_start, 3),
            timestamp=datetime.utcnow(),
        )

        report = self.reporter_agent.synthesize(scan_result)
        self._emit(
            "scan_completed",
            total_attacks=scan_result.total_attacks,
            successful_attacks=scan_result.successful_attacks,
            risk_score=report.risk_score,
        )

        return scan_result

    # ------------------------------------------------------------------
    # Scan execution strategies
    # ------------------------------------------------------------------

    def _sequential_scan(
        self,
        plan: list[tuple],
        reset_between: bool,
        adaptive_retries: bool,
    ) -> list[AttackResult]:
        results: list[AttackResult] = []
        for attack, payload in plan:
            results.extend(self._run_single_attack(attack, payload, self.target, reset_between, adaptive_retries))
        return results

    def _swarm_scan(
        self,
        plan: list[tuple],
        reset_between: bool,
        adaptive_retries: bool,
        max_workers: int,
    ) -> list[AttackResult]:
        """Execute attacks concurrently; each worker gets its own target instance."""
        workers = min(len(plan), max_workers)
        all_results: list[AttackResult] = []

        def run_one(pair: tuple) -> list[AttackResult]:
            attack, payload = pair
            target = self._target_factory()  # type: ignore[misc]
            return self._run_single_attack(attack, payload, target, reset_between, adaptive_retries)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_one, pair) for pair in plan]
            for future in concurrent.futures.as_completed(futures):
                all_results.extend(future.result())

        return all_results

    def _run_single_attack(
        self,
        attack: Any,
        payload: AttackPayload,
        target: SupportsTarget,
        reset_between: bool,
        adaptive_retries: bool,
    ) -> list[AttackResult]:
        if reset_between and hasattr(target, "reset"):
            target.reset()

        self._emit(
            "attack_started",
            attack_type=attack.attack_type.value,
            strategy=payload.strategy_name,
        )

        first_response = self._execute_payload(payload, target)
        first_result = self.evaluator_agent.evaluate(attack, payload, first_response)
        self._emit(
            "attack_evaluated",
            strategy=payload.strategy_name,
            outcome=first_result.outcome.value,
            severity=first_result.severity.value,
            score=first_result.severity_score,
        )

        results = [first_result]

        if adaptive_retries:
            adapted = self.attack_agent.adapt_payload_on_failure(payload, first_response, first_result)
            if adapted is not None:
                if reset_between and hasattr(target, "reset"):
                    target.reset()
                self._emit("attack_adapted", original=payload.strategy_name, adapted=adapted.strategy_name)

                adapted_response = self._execute_payload(adapted, target)
                adapted_result = self.evaluator_agent.evaluate(attack, adapted, adapted_response)
                results.append(adapted_result)
                self._emit(
                    "attack_evaluated",
                    strategy=adapted.strategy_name,
                    outcome=adapted_result.outcome.value,
                    severity=adapted_result.severity.value,
                    score=adapted_result.severity_score,
                )

        return results

    # ------------------------------------------------------------------
    # Target I/O helpers
    # ------------------------------------------------------------------

    def _execute_payload(self, payload: AttackPayload, target: SupportsTarget) -> str:
        """Run all messages in a payload sequentially; return final target response."""
        response = ""
        for message in payload.messages:
            content = str(message.get("content", ""))
            result = self._run_target(content, target)
            response = str(result.get("response", ""))
        return response

    def _run_target(self, message: str, target: SupportsTarget) -> dict:
        """Invoke the target and emit before/after events."""
        self._emit("target_invocation", message=message)
        result = target.invoke(message)
        self._emit(
            "target_response",
            response=str(result.get("response", ""))[:500],
            tool_calls=result.get("tool_calls", []),
        )
        return result

    def _emit(self, event_type: str, **data: Any) -> None:
        if not self.callback:
            return
        event = {
            "event": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            **data,
        }
        with self._emit_lock:
            self.callback(event)

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_with_defaults(user_cfg: dict[str, Any]) -> dict[str, Any]:
        def merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
            merged = dict(base)
            for key, value in override.items():
                if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                    merged[key] = merge(merged[key], value)
                else:
                    merged[key] = value
            return merged

        return merge(DEFAULT_CONFIG, user_cfg)

    @staticmethod
    def _build_default_target(config: dict[str, Any]) -> TargetAgent:
        llm_cfg = config.get("llm", {})
        target_cfg = {
            "provider": llm_cfg.get("provider", "google"),
            "model": llm_cfg.get("model", "gemini-2.0-flash"),
            "api_key_env": llm_cfg.get("api_key_env", "GOOGLE_API_KEY"),
            "temperature": llm_cfg.get("temperature", 0.7),
        }
        return TargetAgent(config=target_cfg)
