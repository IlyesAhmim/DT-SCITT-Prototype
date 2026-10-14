"""Build a publication-oriented artifact bundle from saved experiment outputs.

This module does not run experiments. It collects existing CSV, Markdown, and
PNG artifacts, derives cautious machine-readable summaries from
``aggregate_results.csv``, and writes short drafting aids for papers, slides,
and reviewer-response preparation.
"""

from __future__ import annotations

import csv
import json
import shutil
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


FIGURE_DESCRIPTIONS = {
    "figure_mode_latency.png": (
        "Average local processing time per event across checkpoint modes."
    ),
    "figure_scenario_checkpoint_mix.png": (
        "Policy-driven async, sync, and reject ratios by simulator scenario."
    ),
    "figure_storage_footprint.png": (
        "Average off-chain proof bytes and mock on-chain anchor bytes."
    ),
    "figure_verification_detection.png": (
        "Verification failure categories detected in available verification outputs."
    ),
    "figure_event_type_timing.png": (
        "Average local processing time by Digital Twin event type."
    ),
    "figure_scaling_trend.png": (
        "Average local processing time trend across available experiment sizes."
    ),
}

TABLE_DESCRIPTIONS = {
    "table_mode_comparison.csv": "Mode-level timing, footprint, and checkpoint ratios.",
    "table_mode_comparison.md": "Markdown rendering of mode-level summary metrics.",
    "table_scenario_comparison.csv": (
        "Policy-driven scenario-level checkpoint and event characteristic metrics."
    ),
    "table_scenario_comparison.md": (
        "Markdown rendering of policy-driven scenario summary metrics."
    ),
    "table_verification_failure_summary.csv": (
        "Verification failure category counts when available."
    ),
    "table_verification_failure_summary.md": (
        "Markdown rendering of verification failure category counts."
    ),
}

EXPECTED_AGGREGATE_COLUMNS = {
    "scenario",
    "mode",
    "total_events",
    "processed_events",
    "anchored_events",
    "rejected_events",
    "async_ratio",
    "sync_ratio",
    "reject_ratio",
    "critical_event_count",
    "sensitive_management_count",
    "synchronized_claims_count",
    "out_of_sync_claims_count",
    "avg_processing_time_sec",
    "p95_processing_time_sec",
    "total_offchain_proof_bytes",
    "total_mock_onchain_anchor_bytes",
}


@dataclass(slots=True)
class BundleArtifact:
    """Manifest entry for one publication bundle artifact."""

    file_type: str
    source_path: str | None
    destination_path: str
    description: str
    mandatory: bool
    included: bool
    missing_reason: str | None = None


@dataclass(slots=True)
class PublicationBundleResult:
    """Paths and warnings produced by publication bundle generation."""

    output_dir: Path
    manifest_path: Path
    results_summary_path: Path
    generated_files: list[Path] = field(default_factory=list)
    copied_files: list[Path] = field(default_factory=list)
    artifacts: list[BundleArtifact] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def build_publication_bundle(
    *,
    input_dir: str | Path = "outputs",
    output_dir: str | Path = "outputs/publication_bundle",
    force: bool = False,
) -> PublicationBundleResult:
    """Build a clean bundle from existing experiment, figure, and table outputs."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    if force:
        shutil.rmtree(output_path, ignore_errors=True)

    figures_dir = output_path / "figures"
    tables_dir = output_path / "tables"
    report_dir = output_path / "report"
    run_summaries_dir = report_dir / "run_summaries"
    for directory in [figures_dir, tables_dir, report_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    result = PublicationBundleResult(
        output_dir=output_path,
        manifest_path=output_path / "manifest.json",
        results_summary_path=output_path / "results_summary.json",
    )

    aggregate_path = input_path / "experiments" / "aggregate_results.csv"
    aggregate_destination = tables_dir / "aggregate_results.csv"
    _copy_artifact(
        result,
        source=aggregate_path,
        destination=aggregate_destination,
        file_type="csv",
        description="Aggregate experiment results used for bundle summaries.",
        mandatory=True,
    )

    for figure_name, description in FIGURE_DESCRIPTIONS.items():
        _copy_artifact(
            result,
            source=input_path / "figures" / figure_name,
            destination=figures_dir / figure_name,
            file_type="png",
            description=description,
            mandatory=False,
        )

    for table_name, description in TABLE_DESCRIPTIONS.items():
        _copy_artifact(
            result,
            source=input_path / "tables" / table_name,
            destination=tables_dir / table_name,
            file_type=Path(table_name).suffix.lstrip("."),
            description=description,
            mandatory=False,
        )

    selected_summaries = _select_run_summaries(input_path / "experiments")
    if selected_summaries:
        run_summaries_dir.mkdir(parents=True, exist_ok=True)
        for summary_path in selected_summaries:
            _copy_artifact(
                result,
                source=summary_path,
                destination=run_summaries_dir
                / f"{summary_path.parent.name}_summary.json",
                file_type="json",
                description=(
                    "Selected per-run summary retained for audit and traceability."
                ),
                mandatory=False,
            )
    else:
        _record_missing(
            result,
            source=input_path / "experiments" / "*/summary.json",
            destination=run_summaries_dir,
            file_type="json",
            description="Selected per-run summaries for traceability.",
            mandatory=False,
            reason="no per-run summary.json files found",
        )

    aggregate_rows = _load_csv(aggregate_path)
    results_summary = _build_results_summary(
        aggregate_rows,
        input_path=input_path,
        aggregate_path=aggregate_path,
    )
    _write_json(result.results_summary_path, results_summary)
    _register_generated(
        result,
        result.results_summary_path,
        file_type="json",
        description="Machine-readable summary derived from available outputs.",
        mandatory=True,
    )

    mini_report_path = report_dir / "mini_report.md"
    mini_report_path.write_text(_render_mini_report(results_summary), encoding="utf-8")
    _register_generated(
        result,
        mini_report_path,
        file_type="markdown",
        description="Concise neutral report for paper and slide drafting.",
        mandatory=True,
    )

    methodology_path = output_path / "methodology_summary.md"
    methodology_path.write_text(
        _render_methodology_summary(results_summary), encoding="utf-8"
    )
    _register_generated(
        result,
        methodology_path,
        file_type="markdown",
        description="Methodology and measurement assumptions summary.",
        mandatory=True,
    )

    snippets_path = output_path / "paper_snippets.md"
    snippets_path.write_text(_render_paper_snippets(results_summary), encoding="utf-8")
    _register_generated(
        result,
        snippets_path,
        file_type="markdown",
        description="Reusable neutral text snippets for manuscript drafting.",
        mandatory=True,
    )

    figure_captions_path = output_path / "figure_captions.md"
    figure_captions_path.write_text(
        _render_figure_captions(figures_dir), encoding="utf-8"
    )
    _register_generated(
        result,
        figure_captions_path,
        file_type="markdown",
        description="Suggested captions for available figure artifacts.",
        mandatory=True,
    )

    table_captions_path = output_path / "table_captions.md"
    table_captions_path.write_text(
        _render_table_captions(tables_dir), encoding="utf-8"
    )
    _register_generated(
        result,
        table_captions_path,
        file_type="markdown",
        description="Suggested captions for available table artifacts.",
        mandatory=True,
    )

    _register_generated(
        result,
        result.manifest_path,
        file_type="json",
        description="Auditable manifest of included and missing bundle artifacts.",
        mandatory=True,
    )
    _write_manifest(
        result,
        input_path=input_path,
        results_summary=results_summary,
    )
    return result


def _copy_artifact(
    result: PublicationBundleResult,
    *,
    source: Path,
    destination: Path,
    file_type: str,
    description: str,
    mandatory: bool,
) -> None:
    if source.exists() and source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination.resolve():
            shutil.copy2(source, destination)
        result.copied_files.append(destination)
        result.artifacts.append(
            BundleArtifact(
                file_type=file_type,
                source_path=str(source),
                destination_path=str(destination),
                description=description,
                mandatory=mandatory,
                included=True,
            )
        )
        return

    _record_missing(
        result,
        source=source,
        destination=destination,
        file_type=file_type,
        description=description,
        mandatory=mandatory,
        reason="source artifact not found",
    )


def _record_missing(
    result: PublicationBundleResult,
    *,
    source: Path,
    destination: Path,
    file_type: str,
    description: str,
    mandatory: bool,
    reason: str,
) -> None:
    message = f"{description}: {source} ({reason})"
    if mandatory:
        result.missing_required.append(message)
    else:
        result.missing_optional.append(message)
    result.artifacts.append(
        BundleArtifact(
            file_type=file_type,
            source_path=str(source),
            destination_path=str(destination),
            description=description,
            mandatory=mandatory,
            included=False,
            missing_reason=reason,
        )
    )


def _register_generated(
    result: PublicationBundleResult,
    path: Path,
    *,
    file_type: str,
    description: str,
    mandatory: bool,
) -> None:
    result.generated_files.append(path)
    result.artifacts.append(
        BundleArtifact(
            file_type=file_type,
            source_path=None,
            destination_path=str(path),
            description=description,
            mandatory=mandatory,
            included=True,
        )
    )


def _select_run_summaries(experiments_dir: Path, *, limit: int = 5) -> list[Path]:
    summaries = sorted(experiments_dir.glob("*/summary.json"))
    return summaries[:limit]


def _build_results_summary(
    rows: list[dict[str, str]],
    *,
    input_path: Path,
    aggregate_path: Path,
) -> dict[str, Any]:
    missing_metrics = _missing_aggregate_columns(rows)
    policy_rows = [row for row in rows if row.get("mode") == "policy-driven"]
    verification = _verification_summary(rows, input_path)

    summary: dict[str, Any] = {
        "source": {
            "aggregate_results_csv": str(aggregate_path),
            "aggregate_results_exists": aggregate_path.exists(),
        },
        "total_runs_analyzed": len(rows),
        "scenarios_covered": sorted(_unique_values(rows, "scenario")),
        "modes_covered": sorted(_unique_values(rows, "mode")),
        "average_processing_time_sec_per_mode": _mean_by_group(
            rows, "mode", "avg_processing_time_sec"
        ),
        "p95_processing_time_sec_per_mode": _mean_by_group(
            rows, "mode", "p95_processing_time_sec"
        ),
        "average_proof_bytes_per_mode": _average_proof_bytes_by_mode(rows),
        "average_anchor_bytes_per_mode": _average_anchor_bytes_by_mode(rows),
        "policy_driven_checkpoint_ratios_by_scenario": (
            _policy_ratios_by_scenario(policy_rows)
        ),
        "verification": verification,
        "top_observed_differences": [],
        "missing_metrics": missing_metrics,
    }
    summary["top_observed_differences"] = _observed_differences(summary)
    return summary


def _missing_aggregate_columns(rows: list[dict[str, str]]) -> list[str]:
    if not rows:
        return sorted(EXPECTED_AGGREGATE_COLUMNS)
    return sorted(EXPECTED_AGGREGATE_COLUMNS.difference(rows[0].keys()))


def _unique_values(rows: list[dict[str, str]], field_name: str) -> set[str]:
    return {str(row[field_name]) for row in rows if row.get(field_name)}


def _mean_by_group(
    rows: list[dict[str, str]], group_field: str, value_field: str
) -> dict[str, float]:
    grouped = _group_rows(rows, group_field)
    return {
        key: _round_metric(_mean(_float(row.get(value_field)) for row in group_rows))
        for key, group_rows in sorted(grouped.items())
    }


def _average_proof_bytes_by_mode(rows: list[dict[str, str]]) -> dict[str, float]:
    grouped = _group_rows(rows, "mode")
    values: dict[str, float] = {}
    for mode, mode_rows in sorted(grouped.items()):
        processed = sum(_float(row.get("processed_events")) for row in mode_rows)
        proof_bytes = sum(
            _float(row.get("total_offchain_proof_bytes")) for row in mode_rows
        )
        values[mode] = _round_metric(proof_bytes / processed if processed else 0.0)
    return values


def _average_anchor_bytes_by_mode(rows: list[dict[str, str]]) -> dict[str, float]:
    grouped = _group_rows(rows, "mode")
    values: dict[str, float] = {}
    for mode, mode_rows in sorted(grouped.items()):
        anchored = sum(_float(row.get("anchored_events")) for row in mode_rows)
        anchor_bytes = sum(
            _float(row.get("total_mock_onchain_anchor_bytes")) for row in mode_rows
        )
        values[mode] = _round_metric(anchor_bytes / anchored if anchored else 0.0)
    return values


def _policy_ratios_by_scenario(
    policy_rows: list[dict[str, str]],
) -> dict[str, dict[str, float]]:
    grouped = _group_rows(policy_rows, "scenario")
    ratios: dict[str, dict[str, float]] = {}
    for scenario, scenario_rows in sorted(grouped.items()):
        ratios[scenario] = {
            "async_ratio": _round_metric(
                _mean(_float(row.get("async_ratio")) for row in scenario_rows)
            ),
            "sync_ratio": _round_metric(
                _mean(_float(row.get("sync_ratio")) for row in scenario_rows)
            ),
            "reject_ratio": _round_metric(
                _mean(_float(row.get("reject_ratio")) for row in scenario_rows)
            ),
        }
    return ratios


def _verification_summary(
    rows: list[dict[str, str]], input_path: Path
) -> dict[str, Any]:
    aggregate_checked = sum(_float(row.get("verification_proofs_checked")) for row in rows)
    aggregate_passed = sum(_float(row.get("verification_passed_count")) for row in rows)
    aggregate_failed = sum(_float(row.get("verification_failed_count")) for row in rows)
    categories = _verification_failure_categories(input_path)

    data_exists = bool(
        aggregate_checked
        or aggregate_passed
        or aggregate_failed
        or categories
        or (input_path / "tables" / "table_verification_failure_summary.csv").exists()
    )
    return {
        "data_exists": data_exists,
        "proofs_checked": int(aggregate_checked),
        "passed_count": int(aggregate_passed),
        "failed_count": int(aggregate_failed),
        "failure_categories": categories,
    }


def _verification_failure_categories(input_path: Path) -> dict[str, int]:
    table_path = input_path / "tables" / "table_verification_failure_summary.csv"
    if table_path.exists():
        rows = _load_csv(table_path)
        categories: dict[str, int] = {}
        for row in rows:
            category = str(row.get("failure_category", "")).strip()
            if category:
                categories[category] = int(_float(row.get("count")))
        if categories:
            return categories

    categories: dict[str, int] = {}
    for path in sorted((input_path / "experiments").glob("*/verification_summary.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for category, count in payload.get("failure_categories", {}).items():
            categories[str(category)] = categories.get(str(category), 0) + int(count)
    return categories


def _observed_differences(summary: dict[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    latency_by_mode = summary.get("average_processing_time_sec_per_mode", {})
    observations.extend(
        _range_observation(
            latency_by_mode,
            metric="avg_processing_time_sec",
            comparison="checkpoint_mode",
            basis="aggregate_results.csv",
        )
    )

    proof_bytes_by_mode = summary.get("average_proof_bytes_per_mode", {})
    observations.extend(
        _range_observation(
            proof_bytes_by_mode,
            metric="avg_proof_bytes",
            comparison="checkpoint_mode",
            basis="aggregate_results.csv",
        )
    )

    scenario_ratios = summary.get("policy_driven_checkpoint_ratios_by_scenario", {})
    sync_by_scenario = {
        scenario: values.get("sync_ratio", 0.0)
        for scenario, values in scenario_ratios.items()
    }
    observations.extend(
        _range_observation(
            sync_by_scenario,
            metric="policy_driven_sync_ratio",
            comparison="scenario",
            basis="aggregate_results.csv",
        )
    )
    return observations


def _range_observation(
    values: dict[str, float],
    *,
    metric: str,
    comparison: str,
    basis: str,
) -> list[dict[str, Any]]:
    if len(values) < 2:
        return []
    sorted_values = sorted(values.items(), key=lambda item: item[1])
    lowest_key, lowest_value = sorted_values[0]
    highest_key, highest_value = sorted_values[-1]
    if lowest_value == highest_value:
        return []
    return [
        {
            "metric": metric,
            "comparison": comparison,
            "basis": basis,
            "lowest": {"name": lowest_key, "value": _round_metric(lowest_value)},
            "highest": {"name": highest_key, "value": _round_metric(highest_value)},
            "absolute_difference": _round_metric(highest_value - lowest_value),
        }
    ]


def _render_mini_report(summary: dict[str, Any]) -> str:
    scenarios = _join_or_none(summary.get("scenarios_covered", []))
    modes = _join_or_none(summary.get("modes_covered", []))
    lines = [
        "# Mini Report",
        "",
        "## Prototype Objective",
        (
            "This bundle summarizes local prototype artifacts for an ETSI-aligned "
            "Digital Twin trust checkpoint architecture. The prototype studies how "
            "synthetic Digital Twin events can be converted into proof envelopes, "
            "routed through checkpoint decisions, anchored in a local mock registry, "
            "and verified later."
        ),
        "",
        "## Experimental Setup Summary",
        (
            f"The bundle analyzes {summary['total_runs_analyzed']} saved experiment "
            f"run rows from `aggregate_results.csv`. Scenarios covered: {scenarios}. "
            f"Modes covered: {modes}."
        ),
        (
            "All timing values are local elapsed-time measurements from this "
            "prototype and should be interpreted as relative implementation "
            "measurements under the evaluated scenarios."
        ),
        "",
        "## Scenarios and Modes Evaluated",
        _render_key_value_block("Scenarios", summary.get("scenarios_covered", [])),
        _render_key_value_block("Modes", summary.get("modes_covered", [])),
        "",
        "## Main Quantitative Observations",
        _render_metric_map(
            "Average local processing time per mode",
            summary.get("average_processing_time_sec_per_mode", {}),
            suffix=" s/event",
        ),
        _render_metric_map(
            "Average proof bytes per mode",
            summary.get("average_proof_bytes_per_mode", {}),
            suffix=" bytes/event",
        ),
        _render_policy_ratios(
            summary.get("policy_driven_checkpoint_ratios_by_scenario", {})
        ),
        _render_observations(summary.get("top_observed_differences", [])),
        "",
        "## Verification and Tampering Observations",
        _render_verification_observations(summary.get("verification", {})),
        "",
        "## Key Limitations",
        (
            "- Results come from a local Python prototype with deterministic mock "
            "signatures and a local append-only JSONL anchor registry."
        ),
        "- The event streams are synthetic and scenario-driven, not a full industrial runtime.",
        "- Timing values are not deployment-grade latency measurements.",
        "- No real blockchain consensus, external timestamping, or production PKI is used.",
        "",
        "## Suggested Figure/Table Usage",
        (
            "Use the mode comparison figure and table to discuss local processing "
            "differences across policy-driven, forced-async, and forced-sync modes."
        ),
        (
            "Use the scenario checkpoint-mix artifacts to describe how the "
            "policy-driven trust gate behaves across synthetic event scenarios."
        ),
        (
            "Use verification artifacts only when the corresponding verification "
            "data exists in this bundle."
        ),
        "",
    ]
    return "\n".join(lines)


def _render_methodology_summary(summary: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Methodology Summary",
            "",
            "## Event Simulator Scenarios",
            (
                "The simulator generates deterministic synthetic Digital Twin event "
                "streams for scenario presets such as nominal, high_risk, "
                "management_heavy, lifecycle_instability, and mixed when those "
                "scenarios are present in the saved experiment outputs."
            ),
            (
                f"This bundle covers: {_join_or_none(summary.get('scenarios_covered', []))}."
            ),
            "",
            "## Proof Construction Pipeline",
            (
                "Each processed event is canonicalized into stable JSON, hashed with "
                "SHA-256, assigned a deterministic mock signature, linked to the "
                "previous local anchor for the twin, and persisted as a local JSON "
                "proof envelope."
            ),
            "",
            "## Checkpoint Modes",
            (
                "Policy-driven mode uses the configured checkpoint controller. "
                "Forced-async and forced-sync modes are experimental baselines that "
                "override allowed checkpoint decisions while preserving rejects."
            ),
            "",
            "## Verification Assumptions",
            (
                "The verifier checks local proof files, mock anchor records, hashes, "
                "mock signatures, sequence monotonicity, previous-anchor links, "
                "registry ordering, and a minimal lifecycle/fidelity consistency rule."
            ),
            "",
            "## Measurement Assumptions",
            (
                "Processing time is measured with local elapsed time around prototype "
                "event processing. These values support reproducible relative "
                "comparisons inside this codebase and should not be interpreted as "
                "network or blockchain finality latency."
            ),
            "",
        ]
    )


def _render_paper_snippets(summary: dict[str, Any]) -> str:
    scenarios = _join_or_none(summary.get("scenarios_covered", []))
    modes = _join_or_none(summary.get("modes_covered", []))
    observations = summary.get("top_observed_differences", [])
    observation_text = (
        _observation_sentence(observations[0])
        if observations
        else "The available aggregate outputs do not contain enough variation to summarize a dominant difference."
    )
    verification = summary.get("verification", {})
    verification_text = (
        "Verification outputs are present in the bundle and report "
        f"{verification.get('failed_count', 0)} failed checks across "
        f"{verification.get('proofs_checked', 0)} checked proofs."
        if verification.get("data_exists")
        else "Verification failure outputs were not available in the collected bundle artifacts."
    )
    return "\n".join(
        [
            "# Paper Snippets",
            "",
            "## Prototype Implementation",
            (
                "The prototype implements a local Digital Twin trust checkpoint "
                "pipeline in Python. Events are transformed into deterministic proof "
                "envelopes using canonical JSON, SHA-256 payload hashing, local mock "
                "signatures, and per-twin previous-anchor links. Selected proofs are "
                "recorded in a local append-only mock anchor registry while full "
                "evidence remains in off-chain JSON files."
            ),
            "",
            "## Experimental Setup",
            (
                f"The saved experiment outputs cover the following scenarios: {scenarios}. "
                f"The evaluated execution modes are: {modes}. Metrics are computed from "
                "local prototype runs and include checkpoint counts, local processing "
                "time, proof and anchor footprint, and optional verification summaries."
            ),
            "",
            "## Limitations of the Prototype",
            (
                "The implementation is intentionally lightweight and local. Mock "
                "signatures are deterministic placeholders rather than production "
                "cryptographic signatures, and the anchor registry is not a real "
                "blockchain. The simulator is synthetic, so observations should be "
                "interpreted as controlled prototype behavior rather than industrial "
                "deployment evidence."
            ),
            "",
            "## Main Findings",
            (
                f"Under the evaluated saved outputs, {observation_text} The results "
                "therefore provide a reproducible basis for comparing checkpoint "
                "policy variants in this local prototype, without making claims about "
                "external chain latency or production reliability."
            ),
            "",
            "## Threats to Validity",
            (
                f"{verification_text} The measurements depend on the local machine, "
                "Python runtime, configured simulator seed, and selected scenario "
                "matrix. Future experiments should replace mock signatures and local "
                "anchoring with stronger infrastructure before drawing deployment "
                "claims."
            ),
            "",
        ]
    )


def _render_figure_captions(figures_dir: Path) -> str:
    lines = ["# Figure Captions", ""]
    figure_paths = sorted(figures_dir.glob("*.png"))
    if not figure_paths:
        lines.append("No figure artifacts were available in this bundle.")
        lines.append("")
        return "\n".join(lines)

    for index, path in enumerate(figure_paths, start=1):
        description = FIGURE_DESCRIPTIONS.get(
            path.name, "Collected figure artifact from the reporting pipeline."
        )
        lines.append(f"- Figure {index}. {description}")
    lines.append("")
    return "\n".join(lines)


def _render_table_captions(tables_dir: Path) -> str:
    lines = ["# Table Captions", ""]
    table_paths = [
        path
        for path in sorted(tables_dir.iterdir())
        if path.suffix in {".csv", ".md"}
    ] if tables_dir.exists() else []
    if not table_paths:
        lines.append("No table artifacts were available in this bundle.")
        lines.append("")
        return "\n".join(lines)

    for index, path in enumerate(table_paths, start=1):
        description = TABLE_DESCRIPTIONS.get(
            path.name, "Collected tabular artifact from the experiment pipeline."
        )
        lines.append(f"- Table {index}. {description}")
    lines.append("")
    return "\n".join(lines)


def _render_key_value_block(label: str, values: list[str]) -> str:
    return f"- {label}: {_join_or_none(values)}"


def _render_metric_map(label: str, values: dict[str, float], *, suffix: str) -> str:
    if not values:
        return f"- {label}: unavailable in the collected outputs."
    rendered = ", ".join(
        f"{name}={_format_number(value)}{suffix}" for name, value in sorted(values.items())
    )
    return f"- {label}: {rendered}."


def _render_policy_ratios(values: dict[str, dict[str, float]]) -> str:
    if not values:
        return "- Policy-driven checkpoint ratios by scenario: unavailable."
    fragments = []
    for scenario, ratios in sorted(values.items()):
        fragments.append(
            f"{scenario}(async={_format_number(ratios.get('async_ratio', 0.0))}, "
            f"sync={_format_number(ratios.get('sync_ratio', 0.0))}, "
            f"reject={_format_number(ratios.get('reject_ratio', 0.0))})"
        )
    return "- Policy-driven checkpoint ratios by scenario: " + "; ".join(fragments) + "."


def _render_observations(observations: list[dict[str, Any]]) -> str:
    if not observations:
        return "- Observed differences: insufficient variation in available metrics."
    lines = ["- Observed differences:"]
    for observation in observations[:3]:
        lines.append(f"  - {_observation_sentence(observation)}")
    return "\n".join(lines)


def _render_verification_observations(verification: dict[str, Any]) -> str:
    if not verification.get("data_exists"):
        return (
            "Verification or tampering-summary artifacts were not available in the "
            "collected outputs."
        )
    categories = verification.get("failure_categories", {})
    if categories:
        category_text = ", ".join(
            f"{category}={count}" for category, count in sorted(categories.items())
        )
    else:
        category_text = "no category breakdown available"
    return (
        f"Available verification data reports {verification.get('proofs_checked', 0)} "
        f"checked proofs, {verification.get('passed_count', 0)} passed checks, "
        f"and {verification.get('failed_count', 0)} failed checks; {category_text}."
    )


def _observation_sentence(observation: dict[str, Any]) -> str:
    metric = str(observation.get("metric", "metric")).replace("_", " ")
    comparison = str(observation.get("comparison", "group")).replace("_", " ")
    lowest = observation.get("lowest", {})
    highest = observation.get("highest", {})
    return (
        f"{metric} across {comparison} ranges from "
        f"{lowest.get('name', 'n/a')}={_format_number(lowest.get('value', 0.0))} "
        f"to {highest.get('name', 'n/a')}={_format_number(highest.get('value', 0.0))}."
    )


def _write_manifest(
    result: PublicationBundleResult,
    *,
    input_path: Path,
    results_summary: dict[str, Any],
) -> None:
    payload = {
        "bundle_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input_dir": str(input_path),
        "output_dir": str(result.output_dir),
        "total_artifacts": len(result.artifacts),
        "included_artifacts": sum(1 for artifact in result.artifacts if artifact.included),
        "missing_required": result.missing_required,
        "missing_optional": result.missing_optional,
        "warnings": result.warnings,
        "source_summary": {
            "total_runs_analyzed": results_summary.get("total_runs_analyzed", 0),
            "scenarios_covered": results_summary.get("scenarios_covered", []),
            "modes_covered": results_summary.get("modes_covered", []),
        },
        "artifacts": [asdict(artifact) for artifact in result.artifacts],
    }
    _write_json(result.manifest_path, payload)


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _group_rows(
    rows: Iterable[dict[str, str]], group_field: str
) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        key = str(row.get(group_field, "")).strip()
        if key:
            grouped[key].append(row)
    return dict(grouped)


def _mean(values: Iterable[float]) -> float:
    value_list = list(values)
    return sum(value_list) / len(value_list) if value_list else 0.0


def _float(value: Any) -> float:
    if value in {None, ""}:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _round_metric(value: float) -> float:
    return round(float(value), 10)


def _format_number(value: Any) -> str:
    try:
        return f"{float(value):.6g}"
    except (TypeError, ValueError):
        return str(value)


def _join_or_none(values: list[str]) -> str:
    return ", ".join(values) if values else "none available"
