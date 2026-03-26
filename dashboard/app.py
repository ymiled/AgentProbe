from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from agentprobe.config import load_config
from agentprobe.report.generator import ReportGenerator
from agentprobe.swarm.orchestrator import AgentProbeOrchestrator


def _load_scan_json(path: str) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def _severity_color(sev: str) -> str:
    mapping = {
        "critical": "#ff5d73",
        "high": "#ff9f43",
        "medium": "#ffd166",
        "low": "#59d185",
    }
    return mapping.get(sev.lower(), "#9aa6b2")


def main(default_scan_json: str) -> None:
    st.set_page_config(page_title="AgentProbe Dashboard", layout="wide")
    st.title("AgentProbe Dashboard")

    if "live_events" not in st.session_state:
        st.session_state.live_events = []

    st.sidebar.header("Scan Configuration")
    attacks = st.sidebar.text_input("Attacks", value="all")
    mode = st.sidebar.selectbox("Mode", options=["sequential", "swarm"], index=0)
    recon_messages = st.sidebar.slider("Recon messages", min_value=3, max_value=5, value=3)
    output_dir = st.sidebar.text_input("Output directory", value="output")
    scan_json_path = st.sidebar.text_input("Scan JSON path", value=default_scan_json)

    run_btn = st.sidebar.button("Run Scan")

    scan_data = _load_scan_json(scan_json_path)

    if run_btn:
        st.session_state.live_events = []

        def callback(evt: dict) -> None:
            st.session_state.live_events.append(evt)

        cfg = load_config()
        cfg["scan"]["mode"] = mode
        cfg["scan"]["attacks"] = "all" if attacks.strip().lower() == "all" else [a.strip() for a in attacks.split(",") if a.strip()]
        cfg["scan"]["recon_messages"] = int(recon_messages)
        cfg["output"]["directory"] = output_dir

        with st.spinner("Running scan..."):
            orchestrator = AgentProbeOrchestrator(config=cfg, callback=callback)
            result = orchestrator.scan(mode=mode, attacks=cfg["scan"]["attacks"])
            reporter = ReportGenerator()
            reporter.generate(result, output_dir=output_dir)

            scan_result_path = Path(output_dir) / "scan_result.json"
            scan_result_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
            scan_json_path = str(scan_result_path)
            scan_data = result.model_dump(mode="json")

        st.sidebar.success(f"Scan complete. Saved to {scan_json_path}")

    tabs = st.tabs(["Live Attack Feed", "Charts", "Report"])

    with tabs[0]:
        st.subheader("Live Attack Feed")
        if st.session_state.live_events:
            for evt in reversed(st.session_state.live_events[-200:]):
                event_type = evt.get("event", "unknown")
                color = "#4cc9f0"
                if event_type.startswith("attack"):
                    color = "#ff9f43"
                elif event_type.startswith("recon"):
                    color = "#59d185"
                elif event_type.startswith("target"):
                    color = "#ffd166"
                elif event_type.startswith("scan"):
                    color = "#4cc9f0"

                st.markdown(
                    f"<div style='padding:8px;border-left:4px solid {color};margin-bottom:8px;background:#10151d;'>"
                    f"<strong>{event_type}</strong>"
                    f"<pre style='white-space:pre-wrap;margin:6px 0 0 0;'>{json.dumps(evt, indent=2)}</pre>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No live events yet. Run a scan from the sidebar.")

    with tabs[1]:
        st.subheader("Scan Charts")
        if not scan_data:
            st.info("No scan data loaded. Provide a scan_result.json path or run a scan.")
        else:
            owasp = scan_data.get("owasp_coverage", {})
            rows = [{"owasp": k, "count": v} for k, v in owasp.items()]
            if rows:
                heatmap_df = pd.DataFrame(rows)
                fig_heatmap = px.bar(heatmap_df, x="owasp", y="count", title="OWASP Heatmap")
                st.plotly_chart(fig_heatmap, use_container_width=True)
            else:
                st.info("No OWASP coverage data.")

            success_rate = float(scan_data.get("attack_success_rate", 0.0))
            blocked = int(scan_data.get("blocked_attacks", 0))
            total = int(scan_data.get("total_attacks", 0))
            fail = max(total - int(scan_data.get("successful_attacks", 0)) - blocked, 0)

            status_df = pd.DataFrame(
                [
                    {"status": "success", "count": int(scan_data.get("successful_attacks", 0))},
                    {"status": "blocked", "count": blocked},
                    {"status": "failed", "count": fail},
                ]
            )
            fig_success = px.pie(status_df, names="status", values="count", title=f"Success Rate: {success_rate:.2%}")
            st.plotly_chart(fig_success, use_container_width=True)

            attack_results = scan_data.get("attack_results", [])
            sev_counts: dict[str, int] = {}
            for item in attack_results:
                sev = str(item.get("severity", "low")).lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            if sev_counts:
                sev_df = pd.DataFrame([{"severity": k, "count": v} for k, v in sev_counts.items()])
                fig_sev = px.pie(sev_df, names="severity", values="count", title="Severity Distribution")
                st.plotly_chart(fig_sev, use_container_width=True)

    with tabs[2]:
        st.subheader("Rendered Report")
        html_path = Path(output_dir) / "report.html"
        json_path = Path(output_dir) / "report.json"

        if html_path.exists():
            html = html_path.read_text(encoding="utf-8")
            st.components.v1.html(html, height=800, scrolling=True)
            st.download_button("Download HTML Report", data=html, file_name="report.html", mime="text/html")
        else:
            st.info(f"HTML report not found at {html_path}")

        if json_path.exists():
            raw = json_path.read_text(encoding="utf-8")
            st.download_button("Download JSON Report", data=raw, file_name="report.json", mime="application/json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--scan-json", default="output/scan_result.json")
    args, _ = parser.parse_known_args()
    main(args.scan_json)
