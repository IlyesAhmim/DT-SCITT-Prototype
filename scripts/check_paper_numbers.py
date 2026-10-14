"""Independently recalculate reported values from the frozen reference CSVs."""

from __future__ import annotations

import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "event_level"


def rows(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def median(items: list[dict], field: str, scale: float = 1) -> float:
    return statistics.median(float(item[field]) for item in items) / scale


def percentile(items: list[dict], field: str, q: float, scale: float = 1) -> float:
    values = sorted(float(item[field]) for item in items)
    index = (len(values) - 1) * q
    low, high = math.floor(index), math.ceil(index)
    return (values[low] + (values[high] - values[low]) * (index - low)) / scale


def main() -> int:
    expected = json.loads((DATA / "paper_numbers.json").read_text())
    events, verification = rows("events.csv"), rows("verification.csv")
    faults, tails, seals = rows("faults.csv"), rows("tail_rewrites.csv"), rows("seals.csv")
    failures = []

    def check(label: str, actual, target) -> None:
        ok = math.isclose(actual, target, rel_tol=1e-10, abs_tol=1e-10) if (
            isinstance(actual, (int, float)) and isinstance(target, (int, float))) else actual == target
        if not ok:
            failures.append({"check": label, "actual": actual, "expected": target})

    policy = [r for r in events if r["mode"] == "policy-driven"]
    kept = [r for r in policy if r["evidence"] == "True" and r["decision"] != "reject"]
    per_mode = {}
    for mode in ("policy-driven", "forced-sync", "forced-async"):
        inputs = [r for r in events if r["mode"] == mode]
        ordinary = [r for r in inputs if r["evidence"] == "True" and r["decision"] != "reject"]
        verify = [r for r in verification if r["mode"] == mode]
        per_mode[mode] = {
            "input": len(inputs), "ordinary": len(ordinary),
            "excluded": sum(r["evidence"] != "True" for r in inputs),
            "rejected_candidates": sum(r["decision"] == "reject" for r in inputs),
            "verified": len(verify),
            "rejection_records": sum(r["category"] == "rejection" for r in verify),
            "release_ms_median": median(ordinary, "reliance_us", 1000),
        }
        for field, value in {"input": 5000, "ordinary": 4421, "excluded": 542,
                             "rejected_candidates": 37, "verified": 4458,
                             "rejection_records": 37}.items():
            check(f"{mode}/{field}", per_mode[mode][field], value)

    per_category = {}
    for category, target in expected["per_category"].items():
        selected = [r for r in kept if r["category"] == category]
        verified = [r for r in verification if r["mode"] == "policy-driven" and r["category"] == category]
        sync = [r for r in selected if r["decision"] == "sync"]
        async_ = [r for r in selected if r["decision"] == "async"]
        actual = {
            "kept": len(selected), "sync_share": len(sync) / len(selected),
            "record_bytes_p50": median(selected, "record_bytes"),
            "object_bytes_p50": median(selected, "object_bytes"),
            "anchor_bytes_p50": median(selected, "anchor_bytes"),
            "production_ms_p50": median(selected, "production_us", 1000),
            "reliance_ms_p99": percentile(selected, "reliance_us", .99, 1000),
            "sync_reliance_ms_p50": median(sync, "reliance_us", 1000),
            "async_reliance_ms_p50": median(async_, "reliance_us", 1000) if async_ else None,
            "verify_ms_p50": median(verified, "verify_us", 1000),
        }
        for field, value in actual.items():
            check(f"{category}/{field}", value, target[field])
        per_category[category] = actual

    check("verified_objects", len(verification), 13374)
    check("all_anchored", sum(r["anchored"] == "True" for r in verification), 13374)
    check("all_passed", sum(r["passed"] == "True" for r in verification), 13374)
    check("verification_ms_median", median(verification, "verify_us", 1000), expected["verify_ms_p50"])
    check("fault_cases", len(faults), 2200)
    check("faults_detected", sum(r["detected"] == "True" for r in faults), 2200)
    check("target_check_fired", sum(r["target_check_fired"] == "True" for r in faults), 2200)
    check("fault_classes", len({r["fault"] for r in faults}), 9)
    check("pending_tail_rewritten", sum(int(r["rewritten"]) for r in tails), 179)
    check("tail_rewrites_detected", sum(r["detected"] == "True" for r in tails), 0)
    check("end_flush_count", sum(r["trigger"] == "end" for r in seals), 7)
    report = {
        "scope": "Recalculation of saved data; no new simulation or latency measurement",
        "per_mode": per_mode, "per_category": per_category,
        "verification_ms_median": median(verification, "verify_us", 1000),
        "fault_cases_by_class": dict(Counter(r["fault"] for r in faults)),
        "pending_tail_rewritten": sum(int(r["rewritten"]) for r in tails),
        "failures": failures,
    }
    (ROOT / "checks").mkdir(exist_ok=True)
    (ROOT / "checks" / "paper_numbers_verification.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("per_mode", "verification_ms_median",
                                           "fault_cases_by_class", "pending_tail_rewritten", "failures")}, indent=2))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
