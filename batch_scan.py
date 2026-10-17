"""
batch_scan.py — fleet scanner for empirical observations.

Scans many domains concurrently through the Agent Authority engine and emits:
  1. A JSON Lines file: one line per domain with its full score result.
  2. An aggregate JSON summary: sample size, score distribution, and the
     pass/warn/fail rate of every individual RFC check across the fleet.

This is the empirical engine behind draft revision -01 ("Empirical Observations
Across Origin Fleets"). The aggregate output is the source of truth for the
NLnet documentation — the numbers come from real scans, not estimates.

Design (matches the draft's method and Security Considerations):
  * Bounded concurrency so we never hammer the network or a single origin.
  * Per-domain failures are captured, never fatal: one dead host cannot
    abort a 1000-domain run.
  * Each domain gets its own timeout; the whole run is resumable by re-running
    on the domains missing from the output.
  * Honest accounting: unreachable/errored domains are counted separately and
    are NOT mixed into the "scored" pass-rates.

Usage:
    python batch_scan.py domains.txt
    python batch_scan.py domains.txt --concurrency 16 --out results
    python batch_scan.py domains.txt --limit 100

`domains.txt` is one hostname per line (blank lines and lines starting with
'#' are ignored).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine.scanner import AsyncRFCScanner  # noqa: E402
from engine.scorer import score_telemetry  # noqa: E402


def load_domains(path: str, limit: int | None = None) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for raw in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Accept "rank,domain" (Tranco CSV style) or a bare hostname.
        if "," in line:
            line = line.split(",")[-1].strip()
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        domains.append(line)
        if limit and len(domains) >= limit:
            break
    return domains


async def scan_one(domain: str, timeout: float) -> dict:
    """Scan a single domain. Never raises: failures become a structured record."""
    scanner = AsyncRFCScanner(timeout=timeout)
    t0 = time.perf_counter()
    try:
        telemetry = await scanner.scan_domain(domain)
        result = score_telemetry(telemetry)
        reachable = telemetry.get("root_status") is not None and \
            isinstance(telemetry.get("root_status"), int) and \
            telemetry["root_status"] < 400
        return {
            "domain": domain,
            "hostname": telemetry.get("hostname", domain),
            "reachable": bool(reachable),
            "root_status": telemetry.get("root_status"),
            "errors": telemetry.get("errors", []),
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "overall_score": result.get("overall_score"),
            "grade": result.get("grade"),
            "pillar_scores": result.get("pillar_scores", {}),
            "ledger": result.get("ledger", []),
        }
    except Exception as e:  # defensive: a crash on one domain must not stop the fleet
        return {
            "domain": domain,
            "reachable": False,
            "root_status": None,
            "errors": [f"{type(e).__name__}: {e}"],
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "overall_score": None,
            "grade": None,
            "pillar_scores": {},
            "ledger": [],
        }


async def run_fleet(domains: list[str], concurrency: int, timeout: float,
                    jsonl_path: Path) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    results: list[dict] = []
    done = 0
    total = len(domains)
    lock = asyncio.Lock()

    # Stream each result to disk as it lands, so a long run is never lost.
    jsonl_f = jsonl_path.open("w", encoding="utf-8")

    async def worker(dom: str):
        nonlocal done
        async with sem:
            res = await scan_one(dom, timeout)
        async with lock:
            results.append(res)
            jsonl_f.write(json.dumps(res, ensure_ascii=False) + "\n")
            jsonl_f.flush()
            done += 1
            if done % 25 == 0 or done == total:
                reach = sum(1 for r in results if r["reachable"])
                print(f"  {done}/{total} scanned ({reach} reachable)", flush=True)

    try:
        await asyncio.gather(*(worker(d) for d in domains))
    finally:
        jsonl_f.close()
    return results


def aggregate(results: list[dict]) -> dict:
    """Compute the empirical summary. Pass-rates are over REACHABLE domains only."""
    total = len(results)
    reachable = [r for r in results if r["reachable"]]
    unreachable = [r for r in results if not r["reachable"]]
    n_reach = len(reachable)

    # Score distribution over reachable, scored domains.
    scored = [r for r in reachable if isinstance(r.get("overall_score"), (int, float))]
    scores = sorted(r["overall_score"] for r in scored)

    def pct(xs, p):
        if not xs:
            return None
        k = max(0, min(len(xs) - 1, int(round((p / 100) * (len(xs) - 1)))))
        return xs[k]

    bands = {"agent_native_80_100": 0, "partial_50_79": 0, "agent_blind_0_49": 0}
    for s in scores:
        if s >= 80:
            bands["agent_native_80_100"] += 1
        elif s >= 50:
            bands["partial_50_79"] += 1
        else:
            bands["agent_blind_0_49"] += 1

    # Per-check pass-rate. Key each check by (rfc_ref, title); count PASS vs total.
    check_stats: dict[str, dict] = {}
    for r in reachable:
        for entry in r.get("ledger", []):
            key = f"{entry.get('rfc_ref', '?')} | {entry.get('title', '?')}"
            st = check_stats.setdefault(key, {
                "rfc_ref": entry.get("rfc_ref"),
                "title": entry.get("title"),
                "pillar": entry.get("pillar"),
                "pass": 0, "warn": 0, "fail": 0, "total": 0,
            })
            status = (entry.get("status") or "").upper()
            if status == "PASS":
                st["pass"] += 1
            elif status == "WARN":
                st["warn"] += 1
            elif status == "FAIL":
                st["fail"] += 1
            st["total"] += 1

    for st in check_stats.values():
        st["pass_rate_pct"] = round(100 * st["pass"] / st["total"], 1) if st["total"] else None
        st["fail_rate_pct"] = round(100 * st["fail"] / st["total"], 1) if st["total"] else None

    return {
        "sample": {
            "domains_attempted": total,
            "reachable": n_reach,
            "unreachable_or_errored": len(unreachable),
            "scored": len(scored),
            "reachable_pct": round(100 * n_reach / total, 1) if total else None,
        },
        "score_distribution": {
            "min": scores[0] if scores else None,
            "median": pct(scores, 50),
            "p90": pct(scores, 90),
            "max": scores[-1] if scores else None,
            "mean": round(sum(scores) / len(scores), 1) if scores else None,
            "bands": bands,
        },
        "per_check_pass_rates": sorted(
            check_stats.values(),
            key=lambda s: (s["pass_rate_pct"] if s["pass_rate_pct"] is not None else 999),
        ),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Agent Authority fleet scanner (empirical engine).")
    ap.add_argument("domains_file", help="file with one hostname per line (or Tranco rank,domain CSV)")
    ap.add_argument("--concurrency", type=int, default=12, help="max simultaneous scans (default 12)")
    ap.add_argument("--timeout", type=float, default=8.0, help="per-domain timeout seconds (default 8)")
    ap.add_argument("--limit", type=int, default=None, help="scan only the first N domains")
    ap.add_argument("--out", default="fleet_scan", help="output basename (default fleet_scan)")
    args = ap.parse_args(argv)

    domains = load_domains(args.domains_file, args.limit)
    if not domains:
        print("No domains to scan.", file=sys.stderr)
        return 1

    jsonl_path = Path(f"{args.out}.jsonl")
    summary_path = Path(f"{args.out}.summary.json")

    print(f"Scanning {len(domains)} domains, concurrency={args.concurrency}, "
          f"timeout={args.timeout}s ...", flush=True)
    t0 = time.perf_counter()
    results = asyncio.run(run_fleet(domains, args.concurrency, args.timeout, jsonl_path))
    elapsed = time.perf_counter() - t0

    summary = aggregate(results)
    summary["run"] = {
        "domains_file": args.domains_file,
        "concurrency": args.concurrency,
        "timeout_s": args.timeout,
        "wall_clock_s": round(elapsed, 1),
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    s = summary["sample"]
    d = summary["score_distribution"]
    print(f"\nDone in {elapsed:.1f}s.")
    print(f"  Per-domain results : {jsonl_path}")
    print(f"  Aggregate summary  : {summary_path}")
    print(f"  Reachable          : {s['reachable']}/{s['domains_attempted']} ({s['reachable_pct']}%)")
    print(f"  Median score       : {d['median']}  mean {d['mean']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
