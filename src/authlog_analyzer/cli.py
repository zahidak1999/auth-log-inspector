"""Command-line entry point for the authentication log analyzer."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .analyzer import Analysis, analyze
from .json_parser import parse_content
from .remote import RemoteLogError, fetch_remote_log, safe_url_label


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auth-log-analyzer",
        description="Summarize SSH login failures from a local file or HTTPS endpoint.",
    )
    parser.add_argument("logfile", nargs="?", type=Path, help="Path to an auth.log or compatible log file")
    parser.add_argument("--url", help="HTTPS endpoint that returns a supported text or JSON log")
    parser.add_argument(
        "--token-env",
        metavar="NAME",
        help="Environment variable containing a bearer token for --url",
    )
    parser.add_argument("--timeout", type=float, default=10, help="Remote request timeout in seconds (default: 10)")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=10 * 1024 * 1024,
        help="Maximum remote response size in bytes (default: 10485760)",
    )
    parser.add_argument(
        "--format",
        choices=("auto", "text", "json", "jsonl"),
        default="auto",
        help="Input format; auto detects syslog text, JSON, or JSON Lines (default: auto)",
    )
    parser.add_argument("--json-ip-field", help="Custom dotted field path for the source IP in JSON")
    parser.add_argument("--json-user-field", help="Custom dotted field path for the username in JSON")
    parser.add_argument("--json-status-field", help="Custom dotted field path for success/failure status in JSON")
    parser.add_argument("--json-message-field", help="Custom dotted field path for the original message in JSON")
    parser.add_argument("--json-time-field", help="Custom dotted field path for the timestamp in JSON")
    parser.add_argument("--json-host-field", help="Custom dotted field path for the hostname in JSON")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Minimum failures for a repeated-failure finding (default: 5)",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        metavar="FILE",
        help="Also write the full report as JSON to FILE",
    )
    return parser


def format_report(report: Analysis, source: str) -> str:
    lines = [
        f"Authentication log report: {source}",
        "=" * (26 + len(source)),
        f"Recognized events: {report.total_events}",
        f"  Failed logins:   {report.failed_events}",
        f"  Successful:      {report.successful_events}",
        f"Ignored lines:    {report.ignored_lines}",
        f"Failure threshold: {report.failure_threshold}",
        "",
        "Sources with repeated failures:",
    ]

    if report.repeated_failure_sources:
        for finding in report.repeated_failure_sources:
            users = ", ".join(finding.usernames)
            lines.append(
                f"  {finding.source_ip}: {finding.failed_attempts} failures "
                f"(usernames: {users})"
            )
    else:
        lines.append("None")

    lines.extend(["", "Successful logins after repeated failures:"])
    if report.successes_after_failures:
        for finding in report.successes_after_failures:
            lines.append(
                f"  line {finding.line_number}, {finding.timestamp}: "
                f"{finding.username} from {finding.source_ip} after "
                f"{finding.preceding_failures} failures"
            )
    else:
        lines.append("None")

    lines.extend(["", "Failed attempts by username:"])
    if report.failures_by_username:
        for username, count in report.failures_by_username.items():
            lines.append(f"  {username}: {count}")
    else:
        lines.append("None")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if bool(args.logfile) == bool(args.url):
        parser.error("provide either a local logfile path or --url, but not both")
    if args.token_env and not args.url:
        parser.error("--token-env can only be used with --url")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.max_bytes < 1:
        parser.error("--max-bytes must be greater than zero")

    if args.url:
        token = os.environ.get(args.token_env) if args.token_env else None
        if args.token_env and not token:
            print(f"error: environment variable {args.token_env} is not set", file=sys.stderr)
            return 2
        try:
            text = fetch_remote_log(
                args.url,
                timeout=args.timeout,
                max_bytes=args.max_bytes,
                bearer_token=token,
            )
        except RemoteLogError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        source = safe_url_label(args.url)
    else:
        try:
            text = args.logfile.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            print(f"error: cannot read {args.logfile}: {error}", file=sys.stderr)
            return 2
        source = str(args.logfile)

    try:
        field_map = {
            key: value
            for key, value in {
                "ip": args.json_ip_field,
                "user": args.json_user_field,
                "status": args.json_status_field,
                "message": args.json_message_field,
                "time": args.json_time_field,
                "host": args.json_host_field,
            }.items()
            if value
        }
        events, total_records = parse_content(text, args.format, field_map)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    report = analyze(events, total_lines=total_records, threshold=args.threshold)
    print(format_report(report, source))

    if args.json_path:
        try:
            args.json_path.write_text(
                json.dumps(report.to_dict(), indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as error:
            print(f"error: cannot write {args.json_path}: {error}", file=sys.stderr)
            return 2
        print(f"\nJSON report written to {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
