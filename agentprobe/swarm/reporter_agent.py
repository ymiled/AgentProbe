from __future__ import annotations

from agentprobe.models.schemas import ScanResult, VulnerabilityReport
from agentprobe.report.generator import ReportGenerator


class ReporterAgent:
    """Synthesize attack results into a final VulnerabilityReport JSON structure."""

    def __init__(self):
        self._generator = ReportGenerator()

    def synthesize(self, scan_result: ScanResult) -> VulnerabilityReport:
        return self._generator.build_vulnerability_report(scan_result)
