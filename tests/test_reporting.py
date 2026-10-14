"""Tests for report artifact generation."""

import csv
import importlib.util
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, skipUnless

from dt_trust_checkpoints.cli import main
from dt_trust_checkpoints.reporting import generate_report_artifacts


HAS_MATPLOTLIB = importlib.util.find_spec("matplotlib") is not None


class ReportingTests(TestCase):
    """Report generation tests."""

    def _write_csv(self, path: Path, rows: list[dict[str, object]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def _write_report_fixture(self, root: Path) -> tuple[Path, Path]:
        input_dir = root / "experiments"
        output_dir = root / "outputs"
        aggregate_rows = [
            self._aggregate_row("nominal_policy", "nominal", "policy-driven", 12, 6, 6, 0),
            self._aggregate_row("nominal_async", "nominal", "forced-async", 12, 12, 0, 0),
            self._aggregate_row("nominal_sync", "nominal", "forced-sync", 12, 0, 12, 0),
            self._aggregate_row("high_policy", "high_risk", "policy-driven", 24, 8, 16, 0),
            self._aggregate_row("high_async", "high_risk", "forced-async", 24, 24, 0, 0),
            self._aggregate_row("high_sync", "high_risk", "forced-sync", 24, 0, 24, 0),
        ]
        self._write_csv(input_dir / "aggregate_results.csv", aggregate_rows)

        event_rows = [
            {
                "run_id": "nominal_policy",
                "event_id": "e1",
                "twin_id": "t1",
                "event_type": "af_validated_output",
                "checkpoint_mode": "async",
                "processing_time_sec": 0.001,
            },
            {
                "run_id": "nominal_policy",
                "event_id": "e2",
                "twin_id": "t1",
                "event_type": "dts_transition",
                "checkpoint_mode": "sync",
                "processing_time_sec": 0.002,
            },
            {
                "run_id": "high_policy",
                "event_id": "e3",
                "twin_id": "t1",
                "event_type": "management_action",
                "checkpoint_mode": "sync",
                "processing_time_sec": 0.003,
            },
        ]
        self._write_csv(input_dir / "nominal_policy" / "event_metrics.csv", event_rows)
        (input_dir / "nominal_policy" / "verification_summary.json").write_text(
            json.dumps(
                {
                    "proofs_checked": 12,
                    "passed_count": 10,
                    "failed_count": 2,
                    "failure_categories": {
                        "payload_hash_mismatch": 1,
                        "prev_anchor_mismatch": 1,
                    },
                }
            ),
            encoding="utf-8",
        )
        return input_dir, output_dir

    def _aggregate_row(
        self,
        run_id: str,
        scenario: str,
        mode: str,
        total_events: int,
        async_count: int,
        sync_count: int,
        rejected_events: int,
    ) -> dict[str, object]:
        processed = total_events
        anchored = total_events - rejected_events
        return {
            "run_id": run_id,
            "scenario": scenario,
            "mode": mode,
            "twins": 2,
            "events_per_twin": total_events // 2,
            "seed": 42,
            "total_events": total_events,
            "processed_events": processed,
            "anchored_events": anchored,
            "rejected_events": rejected_events,
            "async_count": async_count,
            "sync_count": sync_count,
            "async_ratio": async_count / processed,
            "sync_ratio": sync_count / processed,
            "reject_ratio": rejected_events / processed,
            "critical_event_count": sync_count,
            "sensitive_management_count": sync_count // 2,
            "synchronized_claims_count": 2,
            "out_of_sync_claims_count": 1,
            "total_processing_time_sec": total_events * 0.001,
            "avg_processing_time_sec": 0.001 + sync_count * 0.00001,
            "p50_processing_time_sec": 0.001,
            "p95_processing_time_sec": 0.002,
            "p99_processing_time_sec": 0.003,
            "total_offchain_proof_bytes": total_events * 1200,
            "total_mock_onchain_anchor_bytes": anchored * 320,
            "offchain_onchain_ratio": 3.75,
            "verification_proofs_checked": 12 if run_id == "nominal_policy" else "",
            "verification_passed_count": 10 if run_id == "nominal_policy" else "",
            "verification_failed_count": 2 if run_id == "nominal_policy" else "",
        }

    @skipUnless(HAS_MATPLOTLIB, "matplotlib is required for figure generation")
    def test_report_generation_creates_expected_figures_and_tables(self):
        with TemporaryDirectory() as tmpdir:
            input_dir, output_dir = self._write_report_fixture(Path(tmpdir))

            result = generate_report_artifacts(
                input_dir=input_dir,
                output_dir=output_dir,
            )

            figure_names = {path.name for path in result.figures}
            table_names = {path.name for path in result.tables}
            self.assertIn("figure_mode_latency.png", figure_names)
            self.assertIn("figure_scenario_checkpoint_mix.png", figure_names)
            self.assertIn("figure_storage_footprint.png", figure_names)
            self.assertIn("figure_verification_detection.png", figure_names)
            self.assertIn("figure_event_type_timing.png", figure_names)
            self.assertIn("figure_scaling_trend.png", figure_names)
            self.assertIn("table_mode_comparison.csv", table_names)
            self.assertIn("table_mode_comparison.md", table_names)
            self.assertIn("table_scenario_comparison.csv", table_names)
            self.assertIn("table_verification_failure_summary.csv", table_names)

            for path in result.figures + result.tables:
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 0)

    def test_missing_optional_data_is_handled_gracefully(self):
        with TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "experiments"
            output_dir = Path(tmpdir) / "outputs"
            self._write_csv(
                input_dir / "aggregate_results.csv",
                [
                    self._aggregate_row(
                        "solo_policy",
                        "nominal",
                        "policy-driven",
                        12,
                        6,
                        6,
                        0,
                    )
                ],
            )

            result = generate_report_artifacts(
                input_dir=input_dir,
                output_dir=output_dir,
            )

            self.assertTrue(result.tables)
            self.assertTrue(any("verification" in item for item in result.skipped))
            self.assertTrue(
                any("event metrics" in item for item in result.skipped)
                or any("matplotlib" in item for item in result.skipped)
            )

    @skipUnless(HAS_MATPLOTLIB, "matplotlib is required for figure generation")
    def test_cli_generate_report_artifacts_runs(self):
        with TemporaryDirectory() as tmpdir:
            input_dir, output_dir = self._write_report_fixture(Path(tmpdir))
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main(
                    [
                        "generate-report-artifacts",
                        "--input-dir",
                        str(input_dir),
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            output = stream.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Report artifact generation complete:", output)
            self.assertTrue((output_dir / "figures" / "figure_mode_latency.png").exists())
            self.assertTrue((output_dir / "tables" / "table_mode_comparison.csv").exists())
