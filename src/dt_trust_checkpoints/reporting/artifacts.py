"""Generate paper-oriented figures and tables from experiment outputs."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass(slots=True)
class ReportArtifactResult:
    """Generated and skipped report artifact paths."""

    figures: list[Path] = field(default_factory=list)
    tables: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def generate_report_artifacts(
    *,
    input_dir: str | Path = "outputs/experiments",
    output_dir: str | Path = "outputs",
    aggregate_csv: str | Path | None = None,
) -> ReportArtifactResult:
    """Generate all available report figures and tables from experiment outputs."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    figures_dir = output_path / "figures"
    tables_dir = output_path / "tables"
    figures_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)

    aggregate_path = Path(aggregate_csv) if aggregate_csv else input_path / "aggregate_results.csv"
    result = ReportArtifactResult()
    rows = _load_csv(aggregate_path)
    if not rows:
        result.skipped.append(f"aggregate CSV missing or empty: {aggregate_path}")
        return result

    _generate_tables(rows, input_path, tables_dir, result)
    _generate_figures(rows, input_path, figures_dir, result)
    return result


def _generate_tables(
    rows: list[dict[str, str]],
    input_dir: Path,
    tables_dir: Path,
    result: ReportArtifactResult,
) -> None:
    mode_rows = _mode_comparison_rows(rows)
    _write_table_pair(tables_dir / "table_mode_comparison", mode_rows, result)

    scenario_rows = _scenario_comparison_rows(rows)
    _write_table_pair(
        tables_dir / "table_scenario_comparison", scenario_rows, result
    )

    verification_rows = _verification_failure_rows(rows, input_dir)
    if verification_rows:
        _write_table_pair(
            tables_dir / "table_verification_failure_summary",
            verification_rows,
            result,
        )
    else:
        result.skipped.append("verification failure table: no verification failures found")


def _generate_figures(
    rows: list[dict[str, str]],
    input_dir: Path,
    figures_dir: Path,
    result: ReportArtifactResult,
) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ModuleNotFoundError as exc:
        result.skipped.append(f"figures: matplotlib is not installed ({exc})")
        return

    _figure_mode_latency(rows, figures_dir, result, plt)
    _figure_scenario_checkpoint_mix(rows, figures_dir, result, plt)
    _figure_storage_footprint(rows, figures_dir, result, plt)
    _figure_verification_detection(rows, input_dir, figures_dir, result, plt)
    _figure_event_type_timing(input_dir, figures_dir, result, plt)
    _figure_scaling_trend(rows, figures_dir, result, plt)


def _figure_mode_latency(
    rows: list[dict[str, str]],
    figures_dir: Path,
    result: ReportArtifactResult,
    plt: Any,
) -> None:
    required = {"mode", "avg_processing_time_sec"}
    if not _has_columns(rows, required):
        result.skipped.append("figure_mode_latency: missing required columns")
        return
    grouped = _mean_by(rows, "mode", "avg_processing_time_sec")
    if not grouped:
        result.skipped.append("figure_mode_latency: no plottable rows")
        return

    labels = list(grouped.keys())
    values = [grouped[label] for label in labels]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(labels, values)
    ax.set_title("Average Processing Time by Checkpoint Mode")
    ax.set_xlabel("Mode")
    ax.set_ylabel("Average processing time per event (s)")
    ax.tick_params(axis="x", rotation=20)
    _save_figure(fig, figures_dir / "figure_mode_latency.png", result)


def _figure_scenario_checkpoint_mix(
    rows: list[dict[str, str]],
    figures_dir: Path,
    result: ReportArtifactResult,
    plt: Any,
) -> None:
    required = {"scenario", "mode", "async_ratio", "sync_ratio", "reject_ratio"}
    if not _has_columns(rows, required):
        result.skipped.append("figure_scenario_checkpoint_mix: missing required columns")
        return

    policy_rows = [row for row in rows if row.get("mode") == "policy-driven"]
    if not policy_rows:
        result.skipped.append("figure_scenario_checkpoint_mix: no policy-driven rows")
        return

    scenarios = sorted({row["scenario"] for row in policy_rows})
    series = ["async_ratio", "sync_ratio", "reject_ratio"]
    x = list(range(len(scenarios)))
    width = 0.25
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for index, field_name in enumerate(series):
        grouped = _mean_by(policy_rows, "scenario", field_name)
        offsets = [value + (index - 1) * width for value in x]
        ax.bar(offsets, [grouped.get(scenario, 0.0) for scenario in scenarios], width, label=field_name.replace("_", " "))
    ax.set_title("Policy-Driven Checkpoint Mix by Scenario")
    ax.set_xlabel("Scenario")
    ax.set_ylabel("Ratio")
    ax.set_xticks(x, scenarios, rotation=25, ha="right")
    ax.legend()
    _save_figure(fig, figures_dir / "figure_scenario_checkpoint_mix.png", result)


def _figure_storage_footprint(
    rows: list[dict[str, str]],
    figures_dir: Path,
    result: ReportArtifactResult,
    plt: Any,
) -> None:
    required = {
        "mode",
        "processed_events",
        "anchored_events",
        "total_offchain_proof_bytes",
        "total_mock_onchain_anchor_bytes",
    }
    if not _has_columns(rows, required):
        result.skipped.append("figure_storage_footprint: missing required columns")
        return

    by_mode = defaultdict(list)
    for row in rows:
        processed = _float(row.get("processed_events"))
        anchored = _float(row.get("anchored_events"))
        proof_avg = _float(row.get("total_offchain_proof_bytes")) / processed if processed else 0.0
        anchor_avg = _float(row.get("total_mock_onchain_anchor_bytes")) / anchored if anchored else 0.0
        by_mode[row["mode"]].append((proof_avg, anchor_avg))

    modes = sorted(by_mode)
    proof_values = [_average([pair[0] for pair in by_mode[mode]]) for mode in modes]
    anchor_values = [_average([pair[1] for pair in by_mode[mode]]) for mode in modes]
    x = list(range(len(modes)))
    width = 0.35
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([value - width / 2 for value in x], proof_values, width, label="off-chain proof")
    ax.bar([value + width / 2 for value in x], anchor_values, width, label="mock anchor")
    ax.set_title("Storage Footprint by Mode")
    ax.set_xlabel("Mode")
    ax.set_ylabel("Average bytes")
    ax.set_xticks(x, modes, rotation=20)
    ax.legend()
    _save_figure(fig, figures_dir / "figure_storage_footprint.png", result)


def _figure_verification_detection(
    rows: list[dict[str, str]],
    input_dir: Path,
    figures_dir: Path,
    result: ReportArtifactResult,
    plt: Any,
) -> None:
    categories = _verification_failure_counts(rows, input_dir)
    if not categories:
        result.skipped.append("figure_verification_detection: no verification failures found")
        return

    labels = list(categories.keys())
    values = [categories[label] for label in labels]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(labels, values)
    ax.set_title("Verification Failure Detection Counts")
    ax.set_xlabel("Failure category")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=25)
    _save_figure(fig, figures_dir / "figure_verification_detection.png", result)


def _figure_event_type_timing(
    input_dir: Path,
    figures_dir: Path,
    result: ReportArtifactResult,
    plt: Any,
) -> None:
    rows = _load_event_metric_rows(input_dir)
    required = {"event_type", "checkpoint_mode", "processing_time_sec"}
    if not rows or not _has_columns(rows, required):
        result.skipped.append("figure_event_type_timing: event metrics unavailable")
        return

    event_types = sorted({row["event_type"] for row in rows})
    modes = sorted({row["checkpoint_mode"] for row in rows})
    x = list(range(len(event_types)))
    width = 0.8 / max(len(modes), 1)
    fig, ax = plt.subplots(figsize=(9, 5))
    for index, mode in enumerate(modes):
        mode_rows = [row for row in rows if row["checkpoint_mode"] == mode]
        grouped = _mean_by(mode_rows, "event_type", "processing_time_sec")
        offsets = [value - 0.4 + width / 2 + index * width for value in x]
        ax.bar(offsets, [grouped.get(event_type, 0.0) for event_type in event_types], width, label=mode)
    ax.set_title("Average Processing Time by Event Type")
    ax.set_xlabel("Event type")
    ax.set_ylabel("Average processing time (s)")
    ax.set_xticks(x, event_types, rotation=30, ha="right")
    ax.legend()
    _save_figure(fig, figures_dir / "figure_event_type_timing.png", result)


def _figure_scaling_trend(
    rows: list[dict[str, str]],
    figures_dir: Path,
    result: ReportArtifactResult,
    plt: Any,
) -> None:
    required = {"total_events", "avg_processing_time_sec"}
    if not _has_columns(rows, required):
        result.skipped.append("figure_scaling_trend: missing required columns")
        return

    grouped = _mean_by(rows, "total_events", "avg_processing_time_sec")
    if len(grouped) < 2:
        result.skipped.append("figure_scaling_trend: insufficient variation in total_events")
        return

    points = sorted((int(float(key)), value) for key, value in grouped.items())
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot([point[0] for point in points], [point[1] for point in points], marker="o")
    ax.set_title("Scaling Trend Across Experiment Sizes")
    ax.set_xlabel("Total events")
    ax.set_ylabel("Average processing time per event (s)")
    _save_figure(fig, figures_dir / "figure_scaling_trend.png", result)


def _mode_comparison_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped = _group_rows(rows, "mode")
    table: list[dict[str, Any]] = []
    for mode, mode_rows in sorted(grouped.items()):
        processed = sum(_float(row.get("processed_events")) for row in mode_rows)
        anchored = sum(_float(row.get("anchored_events")) for row in mode_rows)
        table.append(
            {
                "mode": mode,
                "avg_processing_time_sec": _mean_field(mode_rows, "avg_processing_time_sec"),
                "p95_processing_time_sec": _mean_field(mode_rows, "p95_processing_time_sec"),
                "avg_proof_bytes": _sum_field(mode_rows, "total_offchain_proof_bytes") / processed if processed else 0.0,
                "avg_anchor_bytes": _sum_field(mode_rows, "total_mock_onchain_anchor_bytes") / anchored if anchored else 0.0,
                "async_ratio": _mean_field(mode_rows, "async_ratio"),
                "sync_ratio": _mean_field(mode_rows, "sync_ratio"),
                "reject_ratio": _mean_field(mode_rows, "reject_ratio"),
            }
        )
    return table


def _scenario_comparison_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    policy_rows = [row for row in rows if row.get("mode") == "policy-driven"]
    grouped = _group_rows(policy_rows, "scenario")
    table: list[dict[str, Any]] = []
    for scenario, scenario_rows in sorted(grouped.items()):
        table.append(
            {
                "scenario": scenario,
                "avg_processing_time_sec": _mean_field(scenario_rows, "avg_processing_time_sec"),
                "critical_events": int(_sum_field(scenario_rows, "critical_event_count")),
                "sensitive_management_actions": int(_sum_field(scenario_rows, "sensitive_management_count")),
                "synchronized_claims": int(_sum_field(scenario_rows, "synchronized_claims_count")),
                "out_of_sync_claims": int(_sum_field(scenario_rows, "out_of_sync_claims_count")),
                "sync_ratio": _mean_field(scenario_rows, "sync_ratio"),
            }
        )
    return table


def _verification_failure_rows(
    rows: list[dict[str, str]], input_dir: Path
) -> list[dict[str, Any]]:
    counts = _verification_failure_counts(rows, input_dir)
    total = sum(counts.values())
    if not counts:
        return []
    return [
        {
            "failure_category": category,
            "count": count,
            "percent": (count / total) if total else 0.0,
        }
        for category, count in sorted(counts.items())
    ]


def _verification_failure_counts(
    rows: list[dict[str, str]], input_dir: Path
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in input_dir.glob("*/verification_summary.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        categories = payload.get("failure_categories", {})
        if isinstance(categories, dict):
            for category, count in categories.items():
                counts[str(category)] = counts.get(str(category), 0) + int(count)

    if counts:
        return counts

    failed_total = sum(_float(row.get("verification_failed_count")) for row in rows)
    if failed_total:
        counts["verification_failed"] = int(failed_total)
    return counts


def _write_table_pair(
    stem: Path,
    rows: list[dict[str, Any]],
    result: ReportArtifactResult,
) -> None:
    if not rows:
        result.skipped.append(f"{stem.name}: no rows")
        return
    csv_path = stem.with_suffix(".csv")
    md_path = stem.with_suffix(".md")
    _write_csv(csv_path, rows)
    _write_markdown(md_path, rows)
    result.tables.extend([csv_path, md_path])


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _write_markdown(path: Path, rows: list[dict[str, Any]]) -> None:
    headers = list(rows[0].keys())
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_format_value(row.get(header)) for header in headers) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _save_figure(fig: Any, path: Path, result: ReportArtifactResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    result.figures.append(path)
    fig.clf()


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def _load_event_metric_rows(input_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in input_dir.glob("*/event_metrics.csv"):
        rows.extend(_load_csv(path))
    return rows


def _has_columns(rows: list[dict[str, str]], columns: set[str]) -> bool:
    if not rows:
        return False
    return columns.issubset(rows[0].keys())


def _group_rows(rows: Iterable[dict[str, str]], key: str) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get(key, "")), []).append(row)
    grouped.pop("", None)
    return grouped


def _mean_by(rows: list[dict[str, str]], key: str, field_name: str) -> dict[str, float]:
    grouped = _group_rows(rows, key)
    return {
        group_key: _mean_field(group_rows, field_name)
        for group_key, group_rows in sorted(grouped.items())
    }


def _mean_field(rows: list[dict[str, str]], field_name: str) -> float:
    values = [_float(row.get(field_name)) for row in rows if row.get(field_name) not in {"", None}]
    return _average(values)


def _sum_field(rows: list[dict[str, str]], field_name: str) -> float:
    return sum(_float(row.get(field_name)) for row in rows)


def _average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _float(value: Any) -> float:
    if value in {None, ""}:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _format_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)
