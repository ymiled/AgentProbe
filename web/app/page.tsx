"use client";

import { useEffect, useMemo, useState } from "react";

type AnyRecord = Record<string, any>;

type ScanFinal = {
  event: "scan_final";
  scanId: string;
  timestamp: string;
  totals: {
    total_attacks: number;
    successful_attacks: number;
    blocked_attacks: number;
    attack_success_rate: number;
    attack_success_rate_with_defense: number;
  };
  risk_score: number;
  owasp_coverage: Record<string, number>;
  severity_distribution: Record<string, number>;
  findings_preview: Array<{
    id: string;
    title: string;
    owasp_category: string;
    severity: string;
    severity_score: number;
    attack_type: string;
    evidence: string;
  }>;
  scan_duration_seconds: number;
  artifacts: {
    scan_result_json: string;
    report_json: string;
    report_html: string;
  };
};

type ScanEvent = {
  event: string;
  timestamp?: string;
  scanId?: string;
  [key: string]: any;
};

function normalizeWsUrl(apiUrl: string) {
  if (apiUrl.startsWith("https://")) return apiUrl.replace("https://", "wss://");
  if (apiUrl.startsWith("http://")) return apiUrl.replace("http://", "ws://");
  return apiUrl;
}

function formatPct(n: number) {
  if (!Number.isFinite(n)) return "0%";
  return `${(n * 100).toFixed(1)}%`;
}

export default function Page() {
  const defaultApiUrl = "http://127.0.0.1:8001";
  const apiUrl =
    (process.env.NEXT_PUBLIC_API_URL as string | undefined) ?? defaultApiUrl;
  const wsUrl =
    (process.env.NEXT_PUBLIC_WS_URL as string | undefined) ??
    normalizeWsUrl(apiUrl);

  const [attackPreset, setAttackPreset] = useState("all");
  const [customAttacks, setCustomAttacks] = useState("");
  const [mode, setMode] = useState<"sequential" | "swarm">("sequential");
  const [reconMessages, setReconMessages] = useState(3);
  const [outputDir, setOutputDir] = useState("output");

  const [scanId, setScanId] = useState<string | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [final, setFinal] = useState<ScanFinal | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [status, setStatus] = useState<"idle" | "running" | "failed" | "done" | "canceled" | "canceling">(
    "idle",
  );
  const [error, setError] = useState<string | null>(null);

  const [reportHtmlUrl, setReportHtmlUrl] = useState<string | null>(null);

  const severityKeys = useMemo(() => ["critical", "high", "medium", "low"], []);
  const plannedAttacks = useMemo(() => {
    const planEvt = events.find((e) => e.event === "attack_plan_ready");
    const total = Number(planEvt?.total_payloads ?? 0);
    return Number.isFinite(total) && total > 0 ? total : 0;
  }, [events]);

  const evaluatedAttacks = useMemo(
    () => events.filter((e) => e.event === "attack_evaluated").length,
    [events],
  );

  const currentAttackType = useMemo(() => {
    for (let i = events.length - 1; i >= 0; i -= 1) {
      const evt = events[i];
      if (evt.event === "attack_started") {
        return String(evt.attack_type ?? "unknown");
      }
    }
    return null;
  }, [events]);

  const progressPct = useMemo(() => {
    if (plannedAttacks <= 0) return status === "done" ? 100 : 0;
    return Math.min(100, Math.round((evaluatedAttacks / plannedAttacks) * 100));
  }, [plannedAttacks, evaluatedAttacks, status]);

  const maxSeverity = useMemo(() => {
    if (!final) return 1;
    const values = Object.values(final.severity_distribution ?? {});
    const max = Math.max(1, ...values.map((v) => Number(v) || 0));
    return max;
  }, [final]);

  const owaspMax = useMemo(() => {
    if (!final) return 1;
    const values = Object.values(final.owasp_coverage ?? {});
    const max = Math.max(1, ...values.map((v) => Number(v) || 0));
    return max;
  }, [final]);

  async function runScan() {
    setError(null);
    setFinal(null);
    setEvents([]);
    setReportHtmlUrl(null);
    setWsConnected(false);
    setStatus("running");

    const attacksValue = attackPreset === "custom" ? customAttacks.trim() : attackPreset;
    if (!attacksValue) {
      setStatus("failed");
      setError("Please choose an attack preset or enter custom attacks.");
      return;
    }

    const res = await fetch(`${apiUrl}/api/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        attacks: attacksValue,
        mode,
        recon_messages: reconMessages,
        output_dir: outputDir,
      }),
    });

    if (!res.ok) {
      const txt = await res.text();
      setStatus("failed");
      setError(txt || `HTTP ${res.status}`);
      return;
    }

    const body = await res.json();
    if (!body.scanId) {
      setStatus("failed");
      setError("Missing scanId in response");
      return;
    }

    setScanId(body.scanId);
  }

  async function stopScan() {
    if (!scanId) return;
    setStatus("canceling");
    try {
      const res = await fetch(`${apiUrl}/api/scans/${scanId}/cancel`, { method: "POST" });
      if (!res.ok) {
        const txt = await res.text();
        setError(txt || `HTTP ${res.status}`);
        setStatus("failed");
        return;
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Cancel request failed");
      setStatus("failed");
    }
  }

  useEffect(() => {
    if (!scanId) return;

    const url = `${wsUrl}/ws/scans/${scanId}`;
    const ws = new WebSocket(url);

    ws.onopen = () => setWsConnected(true);

    ws.onmessage = (ev) => {
      let evt: ScanEvent | null = null;
      try {
        evt = JSON.parse(ev.data);
      } catch {
        // ignore
      }
      if (!evt) return;

      setEvents((prev) => {
        const next = [...prev, evt as ScanEvent];
        // keep UI snappy
        return next.slice(Math.max(0, next.length - 200));
      });

      if (evt.event === "scan_final") {
        setFinal(evt as ScanFinal);
        setStatus("done");
      } else if (evt.event === "scan_failed") {
        setStatus("failed");
        setError(evt.error ?? "Scan failed");
      } else if (evt.event === "scan_canceled") {
        setStatus("canceled");
      }
    };

    ws.onerror = () => {
      setWsConnected(false);
    };

    ws.onclose = () => {
      setWsConnected(false);
    };

    return () => {
      try {
        ws.close();
      } catch {
        // ignore
      }
    };
  }, [scanId, wsUrl]);

  const artifact = final?.artifacts;
  const canLoadReport = Boolean(artifact?.report_html);

  return (
    <div className="grid">
      <div className="panel">
        <h2>Live Attack Feed</h2>
        <div className="row">
          <div>
            <label>Attacks</label>
            <select
              value={attackPreset}
              onChange={(e) => setAttackPreset(e.target.value)}
            >
              <option value="all">all</option>
              <option value="prompt_injection">prompt_injection</option>
              <option value="tool_manipulation">tool_manipulation</option>
              <option value="data_exfiltration">data_exfiltration</option>
              <option value="prompt_extraction">prompt_extraction</option>
              <option value="reasoning_hijack">reasoning_hijack</option>
              <option value="custom">custom (comma separated)</option>
            </select>
          </div>
          {attackPreset === "custom" ? (
            <div>
              <label>Custom attacks</label>
              <input
                value={customAttacks}
                onChange={(e) => setCustomAttacks(e.target.value)}
                placeholder="prompt_injection,tool_manipulation"
              />
            </div>
          ) : null}
          <div>
            <label>Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as "sequential" | "swarm")}
            >
              <option value="sequential">sequential</option>
              <option value="swarm">swarm</option>
            </select>
          </div>
          <div>
            <label>Recon messages</label>
            <input
              type="number"
              value={reconMessages}
              min={1}
              max={10}
              onChange={(e) => setReconMessages(Number(e.target.value))}
            />
          </div>
          <div>
            <label>Output dir</label>
            <input value={outputDir} onChange={(e) => setOutputDir(e.target.value)} />
          </div>
          <div style={{ alignSelf: "end" }}>
            <button onClick={runScan} disabled={status === "running"}>
              {status === "running" ? "Running..." : "Run Scan"}
            </button>
            <button
              onClick={stopScan}
              disabled={!scanId || (status !== "running" && status !== "canceling")}
              style={{ marginLeft: 8 }}
            >
              {status === "canceling" ? "Stopping..." : "Stop"}
            </button>
          </div>
        </div>

        <div className="small" style={{ marginTop: 10 }}>
          {scanId ? (
            <>
              ScanId: <span style={{ fontFamily: "monospace" }}>{scanId}</span>
            </>
          ) : (
            <>No active scan.</>
          )}
          {" • "}
          WS: {wsConnected ? "connected" : "disconnected"}
          {status === "canceled" ? (
            <>
              {" • "}
              <span style={{ color: "rgba(255, 220, 140, 0.95)" }}>scan canceled</span>
            </>
          ) : null}
          {status === "failed" && error ? (
            <>
              {" • "}
              <span style={{ color: "rgba(255, 170, 170, 0.95)" }}>{error}</span>
            </>
          ) : null}
        </div>

        <div className="events" style={{ marginTop: 12 }}>
          <div className="small">Scan progress</div>
          <div style={{ marginTop: 8 }}>
            <div
              style={{
                height: 14,
                borderRadius: 999,
                border: "1px solid rgba(255,255,255,0.15)",
                background: "rgba(255,255,255,0.07)",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${progressPct}%`,
                  background: "linear-gradient(90deg, #4cc9f0 0%, #59d185 100%)",
                  transition: "width 200ms ease",
                }}
              />
            </div>
            <div className="small" style={{ marginTop: 8 }}>
              {plannedAttacks > 0
                ? `${evaluatedAttacks}/${plannedAttacks} attack attempts evaluated (${progressPct}%)`
                : status === "running"
                  ? "Preparing attack plan..."
                  : "Waiting for scan..."}
            </div>
          </div>

          <div style={{ marginTop: 12 }}>
            <div className="small">Current attack</div>
            <div style={{ marginTop: 6, fontWeight: 700 }}>
              {currentAttackType ?? (status === "running" ? "Recon / planning..." : "—")}
            </div>
          </div>

          <div style={{ marginTop: 12 }}>
            <div className="small">Recent milestones</div>
            <div style={{ marginTop: 8, display: "grid", gap: 8 }}>
              {events.length === 0 ? (
                <div className="small">Waiting for events...</div>
              ) : (
                events
                  .filter((evt) =>
                    [
                      "scan_started",
                      "recon_complete",
                      "attack_plan_ready",
                      "attack_started",
                      "attack_evaluated",
                      "scan_completed",
                      "scan_failed",
                    ].includes(String(evt.event)),
                  )
                  .slice(-10)
                  .reverse()
                  .map((evt, idx) => {
                    const t = String(evt.event ?? "unknown");
                    let detail = "";
                    if (t === "attack_started") detail = String(evt.attack_type ?? "");
                    if (t === "attack_evaluated") detail = String(evt.outcome ?? "");
                    if (t === "attack_plan_ready") detail = `${evt.total_payloads ?? "?"} payloads`;
                    return (
                      <div
                        key={`${evt.timestamp ?? idx}-${idx}`}
                        style={{
                          padding: "8px 10px",
                          borderRadius: 10,
                          border: "1px solid rgba(255,255,255,0.12)",
                          background: "rgba(255,255,255,0.04)",
                        }}
                      >
                        <div style={{ fontWeight: 700, fontSize: 13 }}>{t}</div>
                        {detail ? <div className="small" style={{ marginTop: 2 }}>{detail}</div> : null}
                      </div>
                    );
                  })
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <h2>Results & Report</h2>
        {!final ? (
          <div className="small">Run a scan to see charts and load the report.</div>
        ) : (
          <>
            <div className="kpi">
              <div className="kpiCard">
                <div className="small">Risk score</div>
                <div className="kpiValue">{final.risk_score.toFixed(2)}</div>
              </div>
              <div className="kpiCard">
                <div className="small">Duration</div>
                <div className="kpiValue">{final.scan_duration_seconds.toFixed(1)}s</div>
              </div>
              <div className="kpiCard">
                <div className="small">Success rate</div>
                <div className="kpiValue">{formatPct(final.totals.attack_success_rate)}</div>
              </div>
              <div className="kpiCard">
                <div className="small">Total attacks</div>
                <div className="kpiValue">{final.totals.total_attacks}</div>
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="small">OWASP coverage</div>
              <div className="barList" style={{ marginTop: 8 }}>
                {Object.entries(final.owasp_coverage ?? {}).length === 0 ? (
                  <div className="small">No OWASP data.</div>
                ) : (
                  Object.entries(final.owasp_coverage)
                    .sort((a, b) => b[1] - a[1])
                    .map(([k, v]) => (
                      <div key={k} className="barRow">
                        <div className="barLabel">{k}</div>
                        <div className="barOuter">
                          <div
                            className="barInner"
                            style={{
                              width: `${Math.min(
                                100,
                                (v / owaspMax) * 100,
                              )}%`,
                            }}
                          />
                        </div>
                        <div className="small" style={{ textAlign: "right" }}>{v}</div>
                      </div>
                    ))
                )}
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="small">Severity distribution</div>
              <div className="barList" style={{ marginTop: 8 }}>
                {severityKeys.map((k) => {
                  const val = Number(final.severity_distribution?.[k] ?? 0);
                  const pct = (val / maxSeverity) * 100;
                  return (
                    <div key={k} className="barRow">
                      <div className="barLabel">{k}</div>
                      <div className="barOuter">
                        <div
                          className="barInner"
                          style={{
                            width: `${Math.min(100, pct)}%`,
                            background:
                              k === "critical"
                                ? "rgba(255, 93, 115, 0.85)"
                                : k === "high"
                                  ? "rgba(255, 159, 67, 0.85)"
                                  : k === "medium"
                                    ? "rgba(255, 209, 102, 0.85)"
                                    : "rgba(89, 209, 133, 0.85)",
                          }}
                        />
                      </div>
                      <div className="small" style={{ textAlign: "right" }}>{val}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="small">Findings preview</div>
              {final.findings_preview?.length ? (
                <div style={{ marginTop: 8, display: "grid", gap: 10 }}>
                  {final.findings_preview.map((f) => (
                    <div key={f.id} style={{ border: "1px solid rgba(255,255,255,0.12)", borderRadius: 12, padding: 10, background: "rgba(255,255,255,0.04)" }}>
                      <div style={{ fontWeight: 800, fontSize: 13 }}>{f.title}</div>
                      <div className="small" style={{ marginTop: 4 }}>
                        {f.id} • {f.owasp_category} • {f.severity} ({f.severity_score.toFixed(1)})
                      </div>
                      <div className="small" style={{ marginTop: 8, fontFamily: "monospace", whiteSpace: "pre-wrap" }}>
                        {f.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="small" style={{ marginTop: 8 }}>No exploitable findings.</div>
              )}
            </div>

            <div style={{ marginTop: 14 }}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <div className="small">Report</div>
                <button
                  disabled={!canLoadReport}
                  onClick={() => {
                    if (!artifact) return;
                    setReportHtmlUrl(`${apiUrl}${artifact.report_html}`);
                  }}
                >
                  Load HTML Report
                </button>
              </div>
            </div>

            {reportHtmlUrl ? (
              <div className="iframeWrap" style={{ marginTop: 10 }}>
                <iframe src={reportHtmlUrl} />
              </div>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}

