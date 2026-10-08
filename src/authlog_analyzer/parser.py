"""Parse common SSH authentication messages from syslog-style auth logs."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

EventKind = Literal["failure", "success"]

_SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<message>.*)$"
)
_FAILURE = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+"
    r"(?:(?:invalid|illegal) user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
_SUCCESS = re.compile(
    r"Accepted\s+(?:password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AuthEvent:
    """One recognized SSH login attempt."""

    line_number: int
    timestamp: str
    host: str
    kind: EventKind
    username: str
    source_ip: str


def normalize_ip(value: str) -> str | None:
    """Return a normalized IP address, or None when the value is malformed."""
    value = value.rstrip(":,;)")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_message(
    message: str,
    line_number: int,
    timestamp: str = "",
    host: str = "",
) -> AuthEvent | None:
    """Parse an SSH authentication message, optionally with supplied metadata."""
    match = _FAILURE.search(message)
    kind: EventKind = "failure"
    if not match:
        match = _SUCCESS.search(message)
        kind = "success"
    if not match:
        return None

    source_ip = normalize_ip(match.group("ip"))
    if source_ip is None:
        return None

    return AuthEvent(
        line_number=line_number,
        timestamp=timestamp,
        host=host,
        kind=kind,
        username=match.group("user"),
        source_ip=source_ip,
    )


def parse_line(line: str, line_number: int) -> AuthEvent | None:
    """Parse a single traditional syslog line into an auth event."""
    header = _SYSLOG_LINE.match(line.strip())
    if not header:
        return None

    timestamp = f"{header.group('month')} {header.group('day')} {header.group('time')}"
    return parse_message(
        header.group("message"),
        line_number=line_number,
        timestamp=timestamp,
        host=header.group("host"),
    )


def parse_lines(lines: list[str]) -> list[AuthEvent]:
    """Return recognized authentication events in their original file order."""
    events = []
    for line_number, line in enumerate(lines, start=1):
        event = parse_line(line, line_number)
        if event is not None:
            events.append(event)
    return events
