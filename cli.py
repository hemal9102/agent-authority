"""
Agent Authority CLI Interface
Run deterministic RFC standards audits directly in the terminal.
"""

import sys
import asyncio
import json
from engine.scanner import AsyncRFCScanner
from engine.scorer import score_telemetry

def format_cli_output(telemetry: dict, score_res: dict):
    target = telemetry["input_target"]
    score = score_res["overall_score"]
    grade = score_res["grade"]
    pillars = score_res["pillar_scores"]
    
    # ANSI Color Escapes
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    color = GREEN if score >= 80 else (YELLOW if score >= 50 else RED)

    print("\n" + "=" * 70)
    print(f"{BOLD}AGENT AUTHORITY (AA) PROTOCOL AUDIT ENGINE{RESET}")
    print(f"Standards: IETF draft-shah-agent-readiness-evaluation-00")
    print("=" * 70)
    print(f"Target URL  : {CYAN}{target}{RESET}")
    print(f"Final URL   : {telemetry.get('final_url')}")
    print(f"TTFB        : {telemetry.get('ttfb_ms')} ms")
    print(f"TLS Version : {telemetry.get('ssl_telemetry', {}).get('tls_version')}")
    print("-" * 70)
    print(f"{BOLD}OVERALL AGENT AUTHORITY SCORE:{RESET} {color}{BOLD}{score} / 100{RESET} ({grade})")
    print("-" * 70)
    print("PILLAR BREAKDOWN:")
    print(f"  1. Agent Discoverability (30%)    : {pillars['discoverability']}/100")
    print(f"  2. Semantic Grounding (30%)       : {pillars['semantic_grounding']}/100")
    print(f"  3. Content Efficiency (25%)       : {pillars['content_efficiency']}/100")
    print(f"  4. Transport & Edge Caching (15%) : {pillars['transport']}/100")
    print("-" * 70)
    print(f"{BOLD}RFC AUDIT FINDINGS & NON-CONFORMANCE LEDGER:{RESET}")

    for idx, item in enumerate(score_res["ledger"], 1):
        status = item["status"]
        s_color = GREEN if status == "PASS" else (YELLOW if status == "WARN" else RED)
        print(f"\n[{s_color}{status}{RESET}] {BOLD}{item['title']}{RESET} ({CYAN}{item['rfc_ref']}{RESET})")
        print(f"     Observation : {item['observation']}")
        if status != "PASS":
            print(f"     Remediation : {item['fix_snippet'].splitlines()[0]}")

    print("\n" + "=" * 70 + "\n")

async def main():
    if len(sys.argv) < 2:
        print("Usage: python cli.py <domain_or_url> [--json]")
        sys.exit(1)

    target = sys.argv[1]
    output_json = "--json" in sys.argv

    scanner = AsyncRFCScanner()
    telemetry = await scanner.scan_domain(target)
    score_res = score_telemetry(telemetry)

    if output_json:
        print(json.dumps({"telemetry": telemetry, "score": score_res}, indent=2))
    else:
        format_cli_output(telemetry, score_res)

if __name__ == "__main__":
    asyncio.run(main())
