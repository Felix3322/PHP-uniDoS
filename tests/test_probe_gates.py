"""Probe preflight checks without sending any network requests."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import attacker
import session_progress_probe


def health(*, php="8.5.11", backtraces="1", early="0"):
    return {
        "http_status": 200,
        "body_prefix": json.dumps({
            "lab": "official-cve-lab-v1",
            "php": php,
            "sapi": "apache2handler",
            "fatal_error_backtraces": backtraces,
            "auto_detect_line_endings": early,
            "memory_limit": "8M",
            "post_max_size": "8M",
            "upload_progress": "1",
        }),
    }


class ProbeGateTests(unittest.TestCase):
    def run_attacker(self, mode, extra_args, fake_send):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            report_path = Path(folder) / "report.json"
            args = ["attacker.py", mode, "--target", "http://127.0.0.1:8088",
                    "--execute", "--report", str(report_path), *extra_args]
            with (patch.object(sys, "argv", args),
                  patch.object(attacker, "send", side_effect=fake_send),
                  redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
                attacker.main()
            return json.loads(report_path.read_text(encoding="utf-8"))

    def test_attacker_rejects_wrong_php_before_candidate(self):
        sent = []

        def fake_send(*args):
            sent.append(args)
            return health(php="8.4.26")

        report = self.run_attacker("109618", ["--part-headers", "1"], fake_send)
        self.assertEqual(len(sent), 1)
        self.assertFalse(report["candidate_attempted"])
        self.assertIn("mismatch", report["stopped_reason"])

    def test_attacker_requires_fatal_producer_before_consumer(self):
        sent = []

        def fake_send(*args):
            sent.append(args)
            if len(sent) == 1:
                return health()
            if len(sent) == 2:
                return health(early="1")
            return {"http_status": 200, "body_prefix": "OK"}

        report = self.run_attacker(
            "109619", ["--consumer", "early/health.php"], fake_send)
        self.assertEqual(len(sent), 3)
        self.assertFalse(report["fatal_producer_observed"])
        self.assertNotIn("early_consumer", [step["step"] for step in report["steps"]])

    def test_session_probe_skips_b_when_a_does_not_oom(self):
        sent = []

        def fake_request(_scheme, _host, _port, method, path, **_kwargs):
            sent.append((method, path))
            if path.endswith("/health.php"):
                return health(), None
            if path.endswith("/session-seed.php"):
                return ({"http_status": 200, "body_prefix": json.dumps({
                    "seeded": True,
                    "session_name": "PHPSESSID",
                    "upload_progress_enabled": "1",
                    "upload_progress_cleanup": "1",
                    "use_only_cookies": "1",
                    "use_strict_mode": "1",
                })}, "PHPSESSID=testsession; path=/")
            return {"http_status": 200, "body_prefix": "OK"}, None

        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            report_path = Path(folder) / "session.json"
            args = ["session_progress_probe.py", "--target", "http://127.0.0.1:8088",
                    "--health", "session/health.php",
                    "--seed", "session/session-seed.php",
                    "--producer", "session/upload.php",
                    "--consumer", "session/upload.php",
                    "--pad-bytes", "1", "--execute", "--report", str(report_path)]
            with (patch.object(sys, "argv", args),
                  patch.object(session_progress_probe, "request", side_effect=fake_request),
                  redirect_stdout(io.StringIO())):
                session_progress_probe.main()
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(len(sent), 3)
        self.assertIn("producer OOM not observed", report["stopped_reason"])
        self.assertNotIn("consumer", [step["step"] for step in report["steps"]])


if __name__ == "__main__":
    unittest.main()
