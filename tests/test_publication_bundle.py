"""Tests for publication bundle generation."""

import csv
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from dt_trust_checkpoints.cli import main
from dt_trust_checkpoints.publication import build_publication_bundle


class PublicationBundleTests(TestCase):
    """Publication artifact bundle tests."""

    def _write_csv(self, path: Path, rows: list[dict[str, object]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def _write_minimal_outputs(self, root: Path, *, optional: bool = True) -> Path:
        output_root = root / "outputs"
        rows = [
            self._aggregate_row(
                "nominal_policy",
                "nominal",
                "policy-driven",
                total_events=10,
                async_count=6,
                sync_count=4,
            ),
            self._aggregate_row(
                "nominal_async",
                "nominal",
                "forced-async",
                total_events=10,
                async_count=10,
                sync_count=0,
            ),
            self._aggregate_row(
                "high_policy",
                "high_risk",
                "policy-driven",
                total_events=10,
                async_count=3,
                sync_count=7,
            ),
        ]
        self._write_csv(output_root / "experiments" / "aggregate_results.csv", rows)

        if optional:
            (output_root / "figures").mkdir(parents=True, exist_ok=True)
            (output_root / "figures" / "figure_mode_latency.png").write_bytes(
                b"placeholder-png"
            )
            (output_root / "figures" / "figure_storage_footprint.png").write_bytes(
                b"placeholder-png"
            )
            self._write_csv(
                output_root / "tables" / "table_mode_comparison.csv",
                [
                    {
                        "mode": "policy-driven",
                        "avg_processing_time_sec": 0.001,
                        "p95_processing_time_sec": 0.002,
                        "avg_proof_bytes": 1200,
                        "avg_anchor_bytes": 320,
                        "async_ratio": 0.45,
                        "sync_ratio": 0.55,
                        "reject_ratio": 0.0,
                    }
                ],
            )
            (output_root / "tables" / "table_mode_comparison.md").write_text(
                "| mode | avg_processing_time_sec |\n| --- | --- |\n"
                "| policy-driven | 0.001 |\n",
                encoding="utf-8",
            )
            self._write_csv(
                output_root / "tables" / "table_verification_failure_summary.csv",
                [{"failure_category": "payload_hash_mismatch", "count": 1, "percent": 1.0}],
            )
            (output_root / "experiments" / "nominal_policy").mkdir(
                parents=True, exist_ok=True
            )
            (output_root / "experiments" / "nominal_policy" / "summary.json").write_text(
                json.dumps({"run_id": "nominal_policy", "total_events": 10}),
                encoding="utf-8",
            )

        return output_root

    def _aggregate_row(
        self,
        run_id: str,
        scenario: str,
        mode: str,
        *,
        total_events: int,
        async_count: int,
        sync_count: int,
    ) -> dict[str, object]:
        processed = total_events
        anchored = total_events
        return {
            "run_id": run_id,
            "scenario": scenario,
            "mode": mode,
            "twins": 1,
            "events_per_twin": total_events,
            "seed": 42,
            "total_events": total_events,
            "processed_events": processed,
            "anchored_events": anchored,
            "rejected_events": 0,
            "async_count": async_count,
            "sync_count": sync_count,
            "async_ratio": async_count / processed,
            "sync_ratio": sync_count / processed,
            "reject_ratio": 0.0,
            "critical_event_count": sync_count,
            "sensitive_management_count": 1,
            "synchronized_claims_count": 2,
            "out_of_sync_claims_count": 1,
            "total_processing_time_sec": total_events * 0.001,
            "avg_processing_time_sec": 0.001 + sync_count * 0.0001,
            "p50_processing_time_sec": 0.001,
            "p95_processing_time_sec": 0.002,
            "p99_processing_time_sec": 0.003,
            "total_offchain_proof_bytes": total_events * 1200,
            "total_mock_onchain_anchor_bytes": anchored * 320,
            "offchain_onchain_ratio": 3.75,
            "verification_proofs_checked": 10 if mode == "policy-driven" else "",
            "verification_passed_count": 9 if mode == "policy-driven" else "",
            "verification_failed_count": 1 if mode == "policy-driven" else "",
        }

    def test_bundle_generation_creates_core_artifacts(self):
        with TemporaryDirectory() as tmpdir:
            input_root = self._write_minimal_outputs(Path(tmpdir))
            bundle_dir = Path(tmpdir) / "bundle"

            result = build_publication_bundle(
                input_dir=input_root,
                output_dir=bundle_dir,
                force=True,
            )

            self.assertFalse(result.missing_required)
            self.assertTrue((bundle_dir / "manifest.json").exists())
            self.assertTrue((bundle_dir / "results_summary.json").exists())
            self.assertTrue((bundle_dir / "report" / "mini_report.md").exists())
            self.assertTrue((bundle_dir / "paper_snippets.md").exists())
            self.assertTrue((bundle_dir / "figure_captions.md").exists())
            self.assertTrue((bundle_dir / "table_captions.md").exists())
            self.assertTrue((bundle_dir / "figures" / "figure_mode_latency.png").exists())
            self.assertTrue((bundle_dir / "tables" / "aggregate_results.csv").exists())

    def test_results_summary_extracts_modes_scenarios_and_ratios(self):
        with TemporaryDirectory() as tmpdir:
            input_root = self._write_minimal_outputs(Path(tmpdir))
            bundle_dir = Path(tmpdir) / "bundle"

            build_publication_bundle(input_dir=input_root, output_dir=bundle_dir)
            summary = json.loads((bundle_dir / "results_summary.json").read_text())

            self.assertEqual(summary["total_runs_analyzed"], 3)
            self.assertIn("nominal", summary["scenarios_covered"])
            self.assertIn("forced-async", summary["modes_covered"])
            self.assertIn(
                "nominal",
                summary["policy_driven_checkpoint_ratios_by_scenario"],
            )
            self.assertTrue(summary["verification"]["data_exists"])

    def test_manifest_records_copied_and_generated_artifacts(self):
        with TemporaryDirectory() as tmpdir:
            input_root = self._write_minimal_outputs(Path(tmpdir))
            bundle_dir = Path(tmpdir) / "bundle"

            build_publication_bundle(input_dir=input_root, output_dir=bundle_dir)
            manifest = json.loads((bundle_dir / "manifest.json").read_text())
            destinations = {
                Path(item["destination_path"]).name
                for item in manifest["artifacts"]
                if item["included"]
            }

            self.assertIn("figure_mode_latency.png", destinations)
            self.assertIn("mini_report.md", destinations)
            self.assertIn("paper_snippets.md", destinations)
            self.assertGreater(manifest["included_artifacts"], 0)

    def test_missing_optional_artifacts_are_handled_gracefully(self):
        with TemporaryDirectory() as tmpdir:
            input_root = self._write_minimal_outputs(Path(tmpdir), optional=False)
            bundle_dir = Path(tmpdir) / "bundle"

            result = build_publication_bundle(
                input_dir=input_root,
                output_dir=bundle_dir,
            )

            self.assertFalse(result.missing_required)
            self.assertTrue(result.missing_optional)
            self.assertTrue((bundle_dir / "manifest.json").exists())
            self.assertTrue((bundle_dir / "figure_captions.md").exists())

    def test_cli_build_publication_bundle_runs(self):
        with TemporaryDirectory() as tmpdir:
            input_root = self._write_minimal_outputs(Path(tmpdir))
            bundle_dir = Path(tmpdir) / "bundle"
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main(
                    [
                        "build-publication-bundle",
                        "--input-dir",
                        str(input_root),
                        "--output-dir",
                        str(bundle_dir),
                        "--force",
                    ]
                )

            output = stream.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Publication bundle complete:", output)
            self.assertTrue((bundle_dir / "manifest.json").exists())
