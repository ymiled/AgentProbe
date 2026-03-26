from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agentprobe.evaluation.owasp_mapping import OWASP_LLM_TOP_10, get_owasp_entry
from agentprobe.evaluation.severity_scorer import SeverityScorer
from agentprobe.models.schemas import (
    AttackOutcome,
    ScanResult,
    VulnerabilityFinding,
    VulnerabilityReport,
)


class ReportGenerator:
    """Generate JSON and HTML reports from a ScanResult."""

    def __init__(self, template_path: str | None = None):
        default_template_path = (
            Path(__file__).resolve().parent / "templates" / "report.html"
        )
        self._template_path = Path(template_path) if template_path else default_template_path
        self._env = Environment(
            loader=FileSystemLoader(str(self._template_path.parent)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._scorer = SeverityScorer()

    def generate(self, scan_result: ScanResult, output_dir: str = "output") -> dict[str, str]:
        """Generate both JSON and HTML reports and return their file paths."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        report = self.build_vulnerability_report(scan_result)
        json_path = out / "report.json"
        html_path = out / "report.html"

        self.generate_json(scan_result, report, str(json_path))
        self.generate_html(scan_result, report, str(html_path))

        return {"json": str(json_path), "html": str(html_path)}

    def generate_json(
        self,
        scan_result: ScanResult,
        report: VulnerabilityReport | None = None,
        output_path: str | None = None,
    ) -> str:
        """Return report JSON string and optionally write it to disk."""
        report_obj = report or self.build_vulnerability_report(scan_result)
        payload = {
            "scan_result": scan_result.model_dump(mode="json"),
            "vulnerability_report": report_obj.model_dump(mode="json"),
        }
        rendered = json.dumps(payload, indent=2)

        if output_path:
            Path(output_path).write_text(rendered, encoding="utf-8")

        return rendered

    def generate_html(
        self,
        scan_result: ScanResult,
        report: VulnerabilityReport | None = None,
        output_path: str | None = None,
    ) -> str:
        """Return rendered HTML and optionally write it to disk."""
        report_obj = report or self.build_vulnerability_report(scan_result)
        template = self._env.get_template(self._template_path.name)

        finding_rows = [
            {
                "id": f.id,
                "title": f.title,
                "owasp_category": f.owasp_category.value,
                "severity": f.severity.value,
                "score": f.severity_score,
                "attack_type": f.attack_type.value,
            }
            for f in report_obj.findings
        ]

        rendered = template.render(
            report=report_obj.model_dump(mode="json"),
            scan=scan_result.model_dump(mode="json"),
            owasp_reference=OWASP_LLM_TOP_10,
            finding_rows=finding_rows,
        )

        if output_path:
            Path(output_path).write_text(rendered, encoding="utf-8")

        return rendered

    def build_vulnerability_report(self, scan_result: ScanResult) -> VulnerabilityReport:
        """Build a structured VulnerabilityReport from raw scan results."""
        findings = self._build_findings(scan_result)
        risk_score = self._compute_risk_score(findings)

        return VulnerabilityReport(
            executive_summary=self._build_executive_summary(scan_result, findings, risk_score),
            risk_score=risk_score,
            findings=findings,
            owasp_heatmap=self._build_heatmap(findings),
            defense_effectiveness={
                "attack_success_rate": scan_result.attack_success_rate,
                "attack_success_rate_with_defense": scan_result.attack_success_rate_with_defense,
                "blocked_attacks": scan_result.blocked_attacks,
            },
            scan_metadata={
                "timestamp": scan_result.timestamp.isoformat(),
                "scan_duration_seconds": scan_result.scan_duration_seconds,
                "total_attacks": scan_result.total_attacks,
                "successful_attacks": scan_result.successful_attacks,
            },
        )

    def _build_findings(self, scan_result: ScanResult) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        idx = 1

        for result in scan_result.attack_results:
            if result.outcome not in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL}:
                continue

            score = result.severity_score
            severity = result.severity
            if score <= 0:
                breakdown = self._scorer.score_attack_result(result)
                score = breakdown.score
                severity = breakdown.severity

            mapping = get_owasp_entry(result.owasp_category)
            messages = [m.get("content", "") for m in result.payload.messages]

            findings.append(
                VulnerabilityFinding(
                    id=f"VULN-{idx:03d}",
                    title=f"{result.payload.strategy_name.replace('_', ' ').title()}",
                    owasp_category=result.owasp_category,
                    severity=severity,
                    severity_score=score,
                    description=(
                        f"{result.payload.description} "
                        f"OWASP context: {mapping.get('description', '')}"
                    ).strip(),
                    reproduction_steps=[
                        f"Send message {i + 1}: {msg}"
                        for i, msg in enumerate(messages)
                        if msg
                    ],
                    evidence=result.evidence,
                    remediation=mapping.get("remediation", "Apply defense-in-depth controls and least privilege."),
                    attack_type=result.payload.attack_type,
                )
            )
            idx += 1

        return findings

    @staticmethod
    def _compute_risk_score(findings: list[VulnerabilityFinding]) -> float:
        if not findings:
            return 0.0
        # Slightly emphasize top findings while still averaging overall risk.
        sorted_scores = sorted((f.severity_score for f in findings), reverse=True)
        top_band = sorted_scores[: min(3, len(sorted_scores))]
        weighted = (0.6 * (sum(top_band) / len(top_band))) + (0.4 * (sum(sorted_scores) / len(sorted_scores)))
        return round(weighted, 2)

    @staticmethod
    def _build_heatmap(findings: list[VulnerabilityFinding]) -> dict[str, int]:
        heatmap: dict[str, int] = {}
        for finding in findings:
            key = finding.owasp_category.value
            heatmap[key] = heatmap.get(key, 0) + 1
        return heatmap

    @staticmethod
    def _build_executive_summary(
        scan_result: ScanResult,
        findings: list[VulnerabilityFinding],
        risk_score: float,
    ) -> str:
        if not findings:
            return (
                f"No exploitable findings were confirmed across {scan_result.total_attacks} attack attempts. "
                "Continue monitoring and regression testing as defenses evolve."
            )

        critical_or_high = sum(1 for f in findings if f.severity.value in {"critical", "high"})
        return (
            f"Detected {len(findings)} actionable vulnerabilities from {scan_result.total_attacks} attack attempts. "
            f"Risk score: {risk_score}/10. "
            f"{critical_or_high} findings are high or critical severity and should be prioritized."
        )
