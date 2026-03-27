"""Scenario A — scan an A2A competitor agent directly (no evaluator server needed).

Requires demo_evaluator_agent.py to be running first:
    python demos/demo_evaluator_agent.py

Then run this:
    python demos/a2a_scan.py
"""

from agentprobe import AgentProbeOrchestrator, A2ATargetAdapter
from agentprobe.report.generator import ReportGenerator

COMPETITOR_AGENT_URL = "http://localhost:8081"

def main() -> None:
    print(f"Connecting to competitor agent at {COMPETITOR_AGENT_URL} ...")

    adapter = A2ATargetAdapter(COMPETITOR_AGENT_URL)

    # Optional: print the Agent Card to confirm connectivity
    try:
        card = adapter.agent_card
        print(f"competitor agent: {card.name} — {card.description[:60]}...")
    except Exception as e:
        print(f"Could not fetch Agent Card: {e}")
        print("Make sure demo_evaluator_agent.py is running.")
        return

    orchestrator = AgentProbeOrchestrator(
        target=adapter,
        callback=lambda e: print(f"  [{e['event']}]", e.get("strategy", e.get("message", ""))),
    )

    print("\nRunning scan...\n")
    result = orchestrator.scan()

    print(f"\n{'='*55}")
    print(f"Attacks run  : {result.total_attacks}")
    print(f"Successful   : {result.successful_attacks}")
    print(f"Blocked      : {result.blocked_attacks}")
    print(f"Success rate : {result.attack_success_rate:.0%}")
    print(f"Duration     : {result.scan_duration_seconds:.1f}s")

    reporter = ReportGenerator()
    report = reporter.build_vulnerability_report(result)
    print(f"Risk score   : {report.risk_score}/10")
    print(f"Findings     : {len(report.findings)}")

    paths = reporter.generate(result, output_dir="output/a2a")
    print(f"\nJSON report  : {paths['json']}")
    print(f"HTML report  : {paths['html']}")
    print("="*55)

if __name__ == "__main__":
    main()
