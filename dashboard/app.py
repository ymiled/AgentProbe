from __future__ import annotations

import json
import queue
import threading
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import HTTPException
from pydantic import BaseModel, Field

from agentprobe.config import load_config
from agentprobe.models.schemas import VulnerabilityFinding
from agentprobe.report.generator import ReportGenerator
from agentprobe.swarm.orchestrator import AgentProbeOrchestrator


class ScanRequest(BaseModel):
    attacks: str = Field(
        default="all",
        description="Comma-separated attack families or 'all'.",
    )
    mode: str = Field(
        default="sequential",
        description="Scan mode: sequential or swarm.",
        pattern="^(sequential|swarm)$",
    )
    recon_messages: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Number of recon probe turns.",
    )
    output_dir: str = Field(
        default="output",
        description="Base directory to store scan artifacts under <output_dir>/<scanId>/",
    )


def _parse_attacks(attacks: str) -> str | list[str]:
    raw = (attacks or "").strip()
    if not raw or raw.lower() == "all":
        return "all"
    return [item.strip() for item in raw.split(",") if item.strip()]


def _as_jsonable(obj: Any) -> Any:
    """Convert common non-JSON types used by AgentProbe models."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    # Pydantic models (and our Enum values) provide `model_dump(mode="json")`.
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        return obj.model_dump(mode="json")
    value = getattr(obj, "value", None)
    if isinstance(value, str):
        return value
    return str(obj)


def _findings_preview(findings: list[VulnerabilityFinding], limit: int = 15) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings[:limit]:
        out.append(
            {
                "id": f.id,
                "title": f.title,
                "owasp_category": _as_jsonable(f.owasp_category),
                "severity": _as_jsonable(f.severity),
                "severity_score": float(f.severity_score),
                "attack_type": _as_jsonable(f.attack_type),
                "evidence": f.evidence[:300],
            }
        )
    return out


# -----------------------------------------------------------------------------
# App + in-memory scan state
# -----------------------------------------------------------------------------

app = FastAPI(
    title="AgentProbe Dashboard API",
    description="Next.js/React dashboard backend for live AgentProbe scans.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local dev friendly; tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_scan_queues: dict[str, queue.Queue[dict[str, Any]]] = {}
_scan_state: dict[str, dict[str, Any]] = {}
_scan_cancel_flags: dict[str, threading.Event] = {}
_scan_lock = threading.Lock()


def _run_scan(
    scan_id: str,
    cfg: dict[str, Any],
    mode: str,
    attacks: str | list[str],
    scan_output_dir: Path,
) -> None:
    """Run scan in a background thread and push events into the scan queue."""
    q = _scan_queues.get(scan_id)
    if q is None:
        return

    cancel_flag = _scan_cancel_flags.get(scan_id)
    if cancel_flag is None:
        return

    def callback(evt: dict) -> None:
        if cancel_flag.is_set():
            raise RuntimeError("Scan canceled by user")
        # Orchestrator emits serializable dicts; attach scanId for convenience.
        evt_out = {"scanId": scan_id, **evt}
        q.put(evt_out)

    try:
        orchestrator = AgentProbeOrchestrator(config=cfg, callback=callback)
        scan_result = orchestrator.scan(mode=mode, attacks=attacks)

        # Build (in-memory) report summary for immediate UI charts.
        reporter = ReportGenerator()
        vulnerability_report = reporter.build_vulnerability_report(scan_result)

        # Persist artifacts to disk for the UI to load after completion.
        scan_result_path = scan_output_dir / "scan_result.json"
        scan_result_path.write_text(
            json.dumps(scan_result.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )

        report_json_path = scan_output_dir / "report.json"
        reporter.generate_json(
            scan_result,
            report=vulnerability_report,
            output_path=str(report_json_path),
        )

        report_html_path = scan_output_dir / "report.html"
        reporter.generate_html(
            scan_result,
            report=vulnerability_report,
            output_path=str(report_html_path),
        )

        # Prepare a final payload the UI can rely on.
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in scan_result.attack_results:
            sev = _as_jsonable(r.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1

        scan_final = {
            "scanId": scan_id,
            "event": "scan_final",
            "timestamp": datetime.utcnow().isoformat(),
            "totals": {
                "total_attacks": int(scan_result.total_attacks),
                "successful_attacks": int(scan_result.successful_attacks),
                "blocked_attacks": int(scan_result.blocked_attacks),
                "attack_success_rate": float(scan_result.attack_success_rate),
                "attack_success_rate_with_defense": float(scan_result.attack_success_rate_with_defense),
            },
            "risk_score": float(vulnerability_report.risk_score),
            "owasp_coverage": {str(k): int(v) for k, v in scan_result.owasp_coverage.items()},
            "severity_distribution": severity_counts,
            "findings_preview": _findings_preview(vulnerability_report.findings),
            "scan_duration_seconds": float(scan_result.scan_duration_seconds),
            "artifacts": {
                "scan_result_json": f"/api/scans/{scan_id}/scan_result.json",
                "report_json": f"/api/scans/{scan_id}/report.json",
                "report_html": f"/api/scans/{scan_id}/report.html",
            },
        }

        with _scan_lock:
            _scan_state[scan_id] = {
                **_scan_state.get(scan_id, {}),
                "state": "completed",
                "risk_score": vulnerability_report.risk_score,
                "scan_result": scan_result,
                "vulnerability_report": vulnerability_report,
                "scan_result_path": str(scan_result_path),
                "report_json_path": str(report_json_path),
                "report_html_path": str(report_html_path),
            }

        q.put(scan_final)
        q.put({"scanId": scan_id, "event": "scan_finished", "timestamp": datetime.utcnow().isoformat()})

    except Exception as exc:
        if str(exc) == "Scan canceled by user":
            with _scan_lock:
                _scan_state[scan_id] = {
                    **_scan_state.get(scan_id, {}),
                    "state": "canceled",
                    "error": None,
                }
            q.put(
                {
                    "scanId": scan_id,
                    "event": "scan_canceled",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
            q.put({"scanId": scan_id, "event": "scan_finished", "timestamp": datetime.utcnow().isoformat()})
            return

        with _scan_lock:
            _scan_state[scan_id] = {
                **_scan_state.get(scan_id, {}),
                "state": "failed",
                "error": str(exc),
            }
        q.put(
            {
                "scanId": scan_id,
                "event": "scan_failed",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(exc),
            }
        )


@app.post("/api/scans")
async def create_scan(req: ScanRequest) -> dict[str, Any]:
    attacks = _parse_attacks(req.attacks)
    cfg = load_config()
    cfg["scan"]["mode"] = req.mode
    cfg["scan"]["attacks"] = attacks
    cfg["scan"]["recon_messages"] = int(req.recon_messages)

    scan_id = str(uuid.uuid4())
    scan_output_dir = Path(req.output_dir) / scan_id
    scan_output_dir.mkdir(parents=True, exist_ok=True)

    q: queue.Queue[dict[str, Any]] = queue.Queue()
    cancel_event = threading.Event()
    with _scan_lock:
        _scan_queues[scan_id] = q
        _scan_cancel_flags[scan_id] = cancel_event
        _scan_state[scan_id] = {
            "state": "submitted",
            "created_at": datetime.utcnow().isoformat(),
            "output_dir": str(scan_output_dir),
        }

    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, cfg, req.mode, attacks, scan_output_dir),
        daemon=True,
    )
    thread.start()

    return {"scanId": scan_id, "state": "submitted"}


@app.get("/api/scans/{scan_id}")
async def get_scan_status(scan_id: str) -> dict[str, Any]:
    with _scan_lock:
        state = _scan_state.get(scan_id)
        if state is None:
            return {"scanId": scan_id, "state": "not_found"}
        # Return a safe subset (do not leak large in-memory objects).
        return {
            "scanId": scan_id,
            "state": state.get("state"),
            "risk_score": float(state["risk_score"]) if state.get("risk_score") is not None else None,
            "output_dir": state.get("output_dir"),
            "created_at": state.get("created_at"),
            "error": state.get("error"),
        }


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str) -> dict[str, Any]:
    with _scan_lock:
        st = _scan_state.get(scan_id)
        flag = _scan_cancel_flags.get(scan_id)
        if st is None or flag is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        if st.get("state") in {"completed", "failed", "canceled"}:
            return {"scanId": scan_id, "state": st.get("state"), "message": "Scan already terminal"}

        flag.set()
        st["state"] = "canceling"
        q = _scan_queues.get(scan_id)

    if q is not None:
        q.put({"scanId": scan_id, "event": "scan_cancel_requested", "timestamp": datetime.utcnow().isoformat()})

    return {"scanId": scan_id, "state": "canceling"}


@app.get("/api/scans/{scan_id}/scan_result.json")
async def get_scan_result(scan_id: str) -> JSONResponse:
    with _scan_lock:
        st = _scan_state.get(scan_id)
        out_dir = st.get("output_dir") if st else None
    if not out_dir:
        raise HTTPException(status_code=404, detail="Scan not found")
    p = Path(out_dir) / "scan_result.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="scan_result.json not found")
    return JSONResponse(json.loads(p.read_text(encoding="utf-8")))


@app.get("/api/scans/{scan_id}/report.json")
async def get_report_json(scan_id: str) -> JSONResponse:
    with _scan_lock:
        st = _scan_state.get(scan_id)
        out_dir = st.get("output_dir") if st else None
    if not out_dir:
        raise HTTPException(status_code=404, detail="Scan not found")
    p = Path(out_dir) / "report.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="report.json not found")
    return JSONResponse(json.loads(p.read_text(encoding="utf-8")))


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
async def get_report_html(scan_id: str) -> HTMLResponse:
    with _scan_lock:
        st = _scan_state.get(scan_id)
        out_dir = st.get("output_dir") if st else None
    if not out_dir:
        raise HTTPException(status_code=404, detail="Scan not found")
    p = Path(out_dir) / "report.html"
    if not p.exists():
        raise HTTPException(status_code=404, detail="report.html not found")
    return HTMLResponse(p.read_text(encoding="utf-8"))


@app.websocket("/ws/scans/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()

    with _scan_lock:
        q = _scan_queues.get(scan_id)
        st = _scan_state.get(scan_id)
        if q is None or st is None:
            await websocket.close(code=4404)
            return
        if st.get("ws_active"):
            await websocket.close(code=1011)
            return
        _scan_state[scan_id]["ws_active"] = True

    loop = __import__("asyncio").get_running_loop()
    try:
        while True:
            # queue.Queue doesn't support await, so we offload to a thread.
            evt = await loop.run_in_executor(None, q.get)
            await websocket.send_json(evt)
            if evt.get("event") in {"scan_finished", "scan_failed", "scan_canceled"}:
                break
    except WebSocketDisconnect:
        # Client disconnected; allow scan to continue.
        pass
    finally:
        with _scan_lock:
            if scan_id in _scan_state:
                _scan_state[scan_id]["ws_active"] = False


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "dashboard.app:app",
        host="0.0.0.0",
        port=8001,
        reload=False,
    )
