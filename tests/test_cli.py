"""Smoke tests for the command-line interface."""

from contextlib import redirect_stdout
from io import StringIO
from unittest import TestCase

from dt_trust_checkpoints.cli import main


class CliTests(TestCase):
    """CLI smoke tests."""

    def test_cli_help_runs(self):
        stream = StringIO()

        try:
            with redirect_stdout(stream):
                main(["--help"])
        except SystemExit as exc:
            self.assertEqual(exc.code, 0)

        self.assertIn("dt-trust-checkpoints", stream.getvalue())
