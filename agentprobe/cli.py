from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import click

from agentprobe.config import load_config
from agentprobe.report.generator import ReportGenerator
from agentprobe.swarm.orchestrator import AgentProbeOrchestrator


def _parse_attacks(value: str) -> list[str] | str:
    raw = value.strip()
    if not raw or raw.lower() == "all":
        return "all"
    return [item.strip() for item in raw.split(",") if item.strip()]


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@click.group()
def cli() -> None:
    """AgentProbe CLI."""


@cli.command()
@click.option("--config", "config_path", default=None, help="Path to YAML config file.")
@click.option("--attacks", default="all", show_default=True, help="Attack types: all or comma-separated values.")
@click.option("--defense/--no-defense", default=False, show_default=True, help="Enable defense mode flag in config.")
@click.option("--mode", type=click.Choice(["sequential", "swarm"]), default="sequential", show_default=True)
@click.option("--output", "output_dir", default="output", show_default=True, help="Output directory for reports.")
@click.option("--format", "report_format", type=click.Choice(["json", "html", "both"]), default="both", show_default=True)
@click.option("--recon-messages", type=int, default=None, help="Override recon probe turns (3-5 recommended).")
@click.option("--fast", is_flag=True, help="Fast scan mode: disable adaptive retries and limit payloads per attack.")
def scan(
    config_path: str | None,
    attacks: str,
    defense: bool,
    mode: str,
    output_dir: str,
    report_format: str,
    recon_messages: int | None,
    fast: bool,
) -> None:
    """Run a red-team scan and write reports."""
    base_cfg = load_config(config_path)
    overrides: dict[str, Any] = {
        "scan": {
            "mode": mode,
            "attacks": _parse_attacks(attacks),
            "defense_enabled": defense,
        },
        "output": {
            "directory": output_dir,
            "format": report_format,
        },
    }
    if recon_messages is not None:
        overrides["scan"]["recon_messages"] = recon_messages

    if fast:
        # Keep attack coverage, but run only first payload per attack and skip adaptive retries.
        overrides["scan"]["payloads_per_attack"] = 1
        overrides["scan"]["adaptive_retries"] = False
        if recon_messages is None:
            overrides["scan"]["recon_messages"] = 3

    cfg = _deep_merge(base_cfg, overrides)

    llm_cfg = cfg.get("llm", {})
    if llm_cfg:
        os.environ["AGENTPROBE_LLM_PROVIDER"] = str(llm_cfg.get("provider", "anthropic"))
        os.environ["AGENTPROBE_LLM_MODEL"] = str(llm_cfg.get("model", "claude-haiku-4-5-20251001"))
        os.environ["AGENTPROBE_LLM_API_KEY_ENV"] = str(llm_cfg.get("api_key_env", "ANTHROPIC_API_KEY"))

    if defense:
        click.echo("[warn] Defense flag is enabled in config, but runtime defense interception is Phase 6.")

    click.echo(f"Running scan in '{mode}' mode...")
    if fast:
        click.echo("Fast mode enabled: payloads_per_attack=1, adaptive_retries=false")
    orchestrator = AgentProbeOrchestrator(config=cfg)
    scan_result = orchestrator.scan(attacks=cfg["scan"]["attacks"], mode=cfg["scan"]["mode"])

    reporter = ReportGenerator()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    report = reporter.build_vulnerability_report(scan_result)
    artifacts: dict[str, str] = {}

    if report_format in {"json", "both"}:
        json_path = out / "report.json"
        reporter.generate_json(scan_result, report, str(json_path))
        artifacts["json"] = str(json_path)

    if report_format in {"html", "both"}:
        html_path = out / "report.html"
        reporter.generate_html(scan_result, report, str(html_path))
        artifacts["html"] = str(html_path)

    scan_json_path = out / "scan_result.json"
    scan_json_path.write_text(json.dumps(scan_result.model_dump(mode="json"), indent=2), encoding="utf-8")

    click.echo("Scan complete.")
    click.echo(
        f"attacks={scan_result.total_attacks} success={scan_result.successful_attacks} "
        f"blocked={scan_result.blocked_attacks} success_rate={scan_result.attack_success_rate:.2%}"
    )
    click.echo(f"scan_result: {scan_json_path}")
    for key, path in artifacts.items():
        click.echo(f"{key}: {path}")


@cli.command()
@click.option("--output", "output_dir", default="output/demo", show_default=True)
@click.option("--mode", type=click.Choice(["sequential", "swarm"]), default="sequential", show_default=True)
def demo(output_dir: str, mode: str) -> None:
    """Run a faster demo scan with a reduced attack set."""
    cfg = load_config()
    cfg = _deep_merge(
        cfg,
        {
            "scan": {
                "mode": mode,
                "attacks": ["prompt_injection", "tool_manipulation"],
                "recon_messages": 3,
            },
            "target": {
                "reset_between_attacks": True,
            },
            "output": {
                "directory": output_dir,
                "format": "both",
            },
        },
    )

    llm_cfg = cfg.get("llm", {})
    if llm_cfg:
        os.environ["AGENTPROBE_LLM_PROVIDER"] = str(llm_cfg.get("provider", "anthropic"))
        os.environ["AGENTPROBE_LLM_MODEL"] = str(llm_cfg.get("model", "claude-haiku-4-5-20251001"))
        os.environ["AGENTPROBE_LLM_API_KEY_ENV"] = str(llm_cfg.get("api_key_env", "ANTHROPIC_API_KEY"))

    click.echo("Running demo scan...")
    orchestrator = AgentProbeOrchestrator(config=cfg)
    scan_result = orchestrator.scan(attacks=cfg["scan"]["attacks"], mode=cfg["scan"]["mode"])

    reporter = ReportGenerator()
    artifacts = reporter.generate(scan_result, output_dir=output_dir)

    scan_json_path = Path(output_dir) / "scan_result.json"
    scan_json_path.write_text(json.dumps(scan_result.model_dump(mode="json"), indent=2), encoding="utf-8")

    click.echo("Demo complete.")
    click.echo(
        f"attacks={scan_result.total_attacks} success={scan_result.successful_attacks} "
        f"blocked={scan_result.blocked_attacks}"
    )
    click.echo(f"scan_result: {scan_json_path}")
    click.echo(f"json: {artifacts['json']}")
    click.echo(f"html: {artifacts['html']}")


@cli.command()
@click.option("--scan-json", default="output/scan_result.json", show_default=True, help="Path to a scan_result.json file.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8501, type=int, show_default=True)
def dashboard(scan_json: str, host: str, port: int) -> None:
    """Launch Streamlit dashboard."""
    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    if not app_path.exists():
        raise click.ClickException(f"Dashboard app not found at: {app_path}")

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.address",
        host,
        "--server.port",
        str(port),
        "--",
        "--scan-json",
        scan_json,
    ]

    click.echo("Launching dashboard...")
    click.echo(" ".join(cmd))
    raise SystemExit(subprocess.call(cmd))


if __name__ == "__main__":
    cli()
