"""Command-line interface tests."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pymdcage.cli import neutralize_terminal

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(ROOT / "src")


def run_cli(*args, input_data=None):
    return subprocess.run(
        [sys.executable, "-m", "pymdcage"] + list(args),
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=ENV,
        cwd=str(ROOT),
        check=False,
    )


class CliTests(unittest.TestCase):
    def test_version(self):
        completed = run_cli("--version")
        self.assertEqual(completed.returncode, 0)
        self.assertIn(b"pymdcage 1.0.0", completed.stdout)

    def test_missing_command_is_usage_error(self):
        completed = run_cli()
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"command is required", completed.stderr)

    def test_unknown_option_is_usage_error(self):
        completed = run_cli("audit", "-", "--unknown")
        self.assertEqual(completed.returncode, 2)

    def test_audit_safe_stdin_exit_zero(self):
        completed = run_cli("audit", "-", input_data=b"hello\n")
        self.assertEqual(completed.returncode, 0)

    def test_audit_unsafe_stdin_exit_one(self):
        completed = run_cli("audit", "-", input_data=b"[x](javascript:alert(1))\n")
        self.assertEqual(completed.returncode, 1)

    def test_audit_json_shape(self):
        completed = run_cli("audit", "-", "--json", input_data=b"[x](javascript:alert(1))\n")
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout.decode("utf-8"))
        self.assertFalse(payload["safe"])
        self.assertEqual(payload["findings"][0]["code"], "PYMDCAGE_DANGEROUS_SCHEME")

    def test_sanitize_stdout(self):
        completed = run_cli("sanitize", "-", input_data=b"[x](javascript:alert(1))\n")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"x\n")

    def test_sanitize_json_does_not_mix_raw_markdown(self):
        completed = run_cli("sanitize", "-", "--json", input_data=b"[x](javascript:alert(1))\n")
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout.decode("utf-8"))
        self.assertEqual(payload["markdown"], "x\n")

    def test_sanitize_out_file(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.md"
            completed = run_cli("sanitize", "-", "--out", str(output), input_data=b"[x](javascript:alert(1))\n")
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(output.read_bytes(), b"x\n")

    def test_extract_links_json(self):
        completed = run_cli("extract-links", "-", "--json", input_data=b"[x](https://example.com)\n")
        self.assertEqual(completed.returncode, 0)
        payload = json.loads(completed.stdout.decode("utf-8"))
        self.assertEqual(payload["links"][0]["url"], "https://example.com")

    def test_extract_links_unsafe_exit_one(self):
        completed = run_cli("extract-links", "-", input_data=b"[x](javascript:alert(1))\n")
        self.assertEqual(completed.returncode, 1)

    def test_max_bytes_is_unsafe_not_usage(self):
        completed = run_cli("audit", "-", "--max-bytes", "2", input_data=b"abc")
        self.assertEqual(completed.returncode, 1)

    def test_missing_file_is_cli_error(self):
        completed = run_cli("audit", "does-not-exist.md")
        self.assertEqual(completed.returncode, 2)

    def test_preset_strict_rejects_http(self):
        completed = run_cli("audit", "-", "--preset", "strict", input_data=b"[x](http://example.com)\n")
        self.assertEqual(completed.returncode, 1)

    def test_neutralize_terminal_controls(self):
        value = "a\nb\rc\td\x00e\x80f\u202eg"
        neutral = neutralize_terminal(value)
        for token in ("\\n", "\\r", "\\t", "\\x00", "\\x80", "\\u202e"):
            self.assertIn(token, neutral)
        self.assertNotIn("\x00", neutral)
        self.assertNotIn("\u202e", neutral)

    def test_stderr_neutralizes_control_characters(self):
        completed = run_cli("audit", "bad\u202epath")
        self.assertNotIn("\u202e".encode("utf-8"), completed.stderr)

    def test_json_output_escapes_controls(self):
        completed = run_cli("audit", "-", "--json", input_data=b"a\x00b\n")
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn(b"\x00", completed.stdout)


if __name__ == "__main__":
    unittest.main()
