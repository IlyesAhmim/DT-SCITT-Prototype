"""Tests for local experiment runners."""

import csv
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from dt_trust_checkpoints.cli import main
from dt_trust_checkpoints.config import load_config
from dt_trust_checkpoints.experiments import ExperimentRunConfig, ExperimentRunner


class ExperimentRunnerTests(TestCase):
    """Experiment runner output and mode tests."""

    def _runner(self) -> ExperimentRunner:
        return ExperimentRunner(load_config(Path("configs/default.json")))

    def test_single_experiment_run_writes_outputs_and_aggregate(self):
        with TemporaryDirectory() as tmpdir:
            result = self._runner().run_one(
                ExperimentRunConfig(
                    scenario="mixed",
                    mode="policy-driven",
                    twins=1,
                    events_per_twin=4,
                    seed=3,
                    output_dir=tmpdir,
                    with_verification=True,
                )
            )

            self.assertTrue((result.run_dir / "summary.json").exists())
            self.assertTrue((result.run_dir / "event_metrics.csv").exists())
            self.assertTrue((result.run_dir / "proof_metrics.csv").exists())
            self.assertTrue((result.run_dir / "anchors_metrics.csv").exists())
            self.assertTrue((result.run_dir / "verification_summary.json").exists())
            self.assertTrue((Path(tmpdir) / "aggregate_results.csv").exists())

            summary = json.loads((result.run_dir / "summary.json").read_text())
            self.assertEqual(summary["total_events"], 4)
            self.assertEqual(summary["processed_events"], 4)
            self.assertGreater(summary["anchored_events"], 0)
            self.assertGreaterEqual(summary["timing"]["avg_processing_time_sec"], 0.0)
            self.assertGreater(summary["storage"]["total_offchain_proof_bytes"], 0)
            self.assertGreater(summary["storage"]["total_mock_onchain_anchor_bytes"], 0)

    def test_forced_async_mode_produces_zero_sync_events(self):
        with TemporaryDirectory() as tmpdir:
            result = self._runner().run_one(
                ExperimentRunConfig(
                    scenario="mixed",
                    mode="forced-async",
                    twins=1,
                    events_per_twin=6,
                    seed=3,
                    output_dir=tmpdir,
                )
            )

            self.assertEqual(result.summary["sync_count"], 0)
            self.assertEqual(result.summary["async_count"], result.summary["processed_events"])

    def test_forced_sync_mode_produces_zero_async_events(self):
        with TemporaryDirectory() as tmpdir:
            result = self._runner().run_one(
                ExperimentRunConfig(
                    scenario="mixed",
                    mode="forced-sync",
                    twins=1,
                    events_per_twin=6,
                    seed=3,
                    output_dir=tmpdir,
                )
            )

            self.assertEqual(result.summary["async_count"], 0)
            self.assertEqual(result.summary["sync_count"], result.summary["processed_events"])

    def test_policy_driven_mode_can_produce_async_sync_mix(self):
        with TemporaryDirectory() as tmpdir:
            result = self._runner().run_one(
                ExperimentRunConfig(
                    scenario="mixed",
                    mode="policy-driven",
                    twins=1,
                    events_per_twin=4,
                    seed=3,
                    output_dir=tmpdir,
                )
            )

            self.assertGreater(result.summary["async_count"], 0)
            self.assertGreater(result.summary["sync_count"], 0)

    def test_aggregate_results_file_contains_run_row(self):
        with TemporaryDirectory() as tmpdir:
            self._runner().run_one(
                ExperimentRunConfig(
                    scenario="nominal",
                    mode="policy-driven",
                    twins=1,
                    events_per_twin=2,
                    seed=9,
                    output_dir=tmpdir,
                )
            )
            aggregate_path = Path(tmpdir) / "aggregate_results.csv"

            with aggregate_path.open("r", newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["scenario"], "nominal")
            self.assertIn("avg_processing_time_sec", rows[0])

    def test_cli_run_experiments_works(self):
        with TemporaryDirectory() as tmpdir:
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main(
                    [
                        "run-experiments",
                        "--scenario",
                        "mixed",
                        "--mode",
                        "policy-driven",
                        "--twins",
                        "1",
                        "--events-per-twin",
                        "3",
                        "--seed",
                        "5",
                        "--output-dir",
                        tmpdir,
                    ]
                )

            output = stream.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Experiment run complete:", output)
            self.assertTrue((Path(tmpdir) / "aggregate_results.csv").exists())

    def test_cli_default_experiment_suite_works(self):
        with TemporaryDirectory() as tmpdir:
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main(
                    [
                        "run-default-experiment-suite",
                        "--twins",
                        "1",
                        "--events-per-twin",
                        "1",
                        "--seed",
                        "6",
                        "--output-dir",
                        tmpdir,
                    ]
                )

            output = stream.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Default experiment suite complete:", output)
            self.assertIn("runs=15", output)
            self.assertTrue((Path(tmpdir) / "aggregate_results.csv").exists())
