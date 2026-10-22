"""Regression checks for the console's observable security conclusions.

No test opens a network connection or sends a DoS request.
"""

from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

import interactive


def health(php="8.5.11", pid="111", backtraces="1", early="0"):
    return ({
        "http_status": 200,
        "worker_pid_header": pid,
        "body_prefix": json.dumps({
            "lab": "official-cve-lab-v1",
            "php": php,
            "sapi": "apache2handler",
            "memory_limit": "8M",
            "post_max_size": "8M",
            "upload_progress": "1",
            "fatal_error_backtraces": backtraces,
            "auto_detect_line_endings": early,
        }),
    }, None)


def seed(pid="111"):
    return ({
        "http_status": 200,
        "worker_pid_header": pid,
        "body_prefix": json.dumps({
            "seeded": True,
            "session_name": "PHPSESSID",
            "upload_progress_enabled": "1",
            "upload_progress_cleanup": "1",
            "use_only_cookies": "1",
            "use_strict_mode": "1",
        }),
    }, "PHPSESSID=testsession; path=/")


class ConsoleVerdictTests(unittest.TestCase):
    def console(self):
        console = interactive.Console()
        with redirect_stdout(io.StringIO()):
            console.cmd_target("http://127.0.0.1:8088")
        return console

    def run_session(self, *, php="8.5.11", producer_text="OK", consumer=None):
        console = self.console()
        uploads = []
        consumer = consumer or {"transport_error": "TimeoutError"}

        def fake_request(_scheme, _host, _port, method, path, **_kwargs):
            if path.endswith("/session/health.php"):
                return health(php)
            if path.endswith("/session/session-seed.php"):
                return seed()
            if path.endswith("/session/upload.php") and method == "POST":
                uploads.append(path)
                if len(uploads) == 1:
                    return ({"http_status": 200, "worker_pid_header": "111",
                             "body_prefix": producer_text}, None)
                return consumer, None
            raise AssertionError(f"unexpected request: {method} {path}")

        output = io.StringIO()
        with (patch.object(interactive, "session_request", side_effect=fake_request),
              patch.object(interactive, "multipart_producer", return_value=b"A"),
              patch.object(interactive, "multipart_consumer", return_value=b"B"),
              redirect_stdout(output)):
            console.cmd_session()
        return output.getvalue(), len(uploads)

    def test_session_stops_before_b_if_a_did_not_oom(self):
        output, upload_count = self.run_session(producer_text="OK")
        self.assertEqual(upload_count, 1)
        self.assertNotIn("Worker crashed", output)

    def test_session_timeout_does_not_prove_worker_crash(self):
        output, upload_count = self.run_session(
            producer_text="Allowed memory size of 8388608 bytes exhausted",
            consumer={"transport_error": "TimeoutError"},
        )
        self.assertEqual(upload_count, 2)
        self.assertNotIn("Worker crashed", output)

    def test_session_version_mismatch_stops_before_upload(self):
        _, upload_count = self.run_session(php="8.4.26")
        self.assertEqual(upload_count, 0)

    def test_109618_pid_change_is_not_crash_proof(self):
        console = self.console()
        console.part_headers = 1
        calls = 0

        def fake_send(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return {"http_status": 200, "worker_pid_header": "111",
                        "body_prefix": health()[0]["body_prefix"]}
            if calls == 2:
                return {"http_status": 200, "elapsed_ms": 1,
                        "body_prefix": "Allowed memory size exhausted"}
            return {"http_status": 200, "worker_pid_header": "222",
                    "body_prefix": health(pid="222")[0]["body_prefix"]}

        output = io.StringIO()
        with patch.object(interactive, "send", side_effect=fake_send), redirect_stdout(output):
            console.cmd_109618("part-headers")
        self.assertEqual(calls, 3)
        self.assertNotIn("Worker crashed", output.getvalue())

    def test_109619_requires_an_early_consumer_before_producer(self):
        console = self.console()
        with redirect_stdout(io.StringIO()):
            console.cmd_set("consumer", "early/health.php")
        requested_paths = []

        def fake_send(*args, **_kwargs):
            requested_paths.append(args[4])
            return {**health(early="0")[0], "elapsed_ms": 1}

        output = io.StringIO()
        with patch.object(interactive, "send", side_effect=fake_send), redirect_stdout(output):
            console.cmd_109619()
        self.assertEqual(requested_paths, ["/health.php", "/early/health.php"])
        self.assertIn("Preflight stopped", output.getvalue())


if __name__ == "__main__":
    unittest.main()
