"""Summarize SSH authentication events and identify simple signals."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass

from .parser import AuthEvent


@dataclass(frozen=True)
class Finding:
    """A source address that crossed a configured failure threshold."""

    source_ip: str
    failed_attempts: int
    usernames: list[str]


@dataclass(frozen=True)
class SuccessAfterFailures:
    """A successful login following a threshold number of failures by a source."""

    source_ip: str
    username: str
    timestamp: str
    line_number: int
    preceding_failures: int


@dataclass(frozen=True)
class Analysis:
    total_events: int
    failed_events: int
    successful_events: int
    ignored_lines: int
    failure_threshold: int
    repeated_failure_sources: list[Finding]
    successes_after_failures: list[SuccessAfterFailures]
    failures_by_username: dict[str, int]

    def to_dict(self) -> dict:
        return asdict(self)


def analyze(events: list[AuthEvent], total_lines: int, threshold: int = 5) -> Analysis:
    if threshold < 1:
        raise ValueError("threshold must at least be 1")

    failures_by_ip: Counter[str] = Counter()
    failures_by_user: Counter[str] = Counter()
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    failures_since_success: Counter[str] = Counter()
    successes_after_failures: list[SuccessAfterFailures] = []
    failed_events = 0
    successful_events = 0

    for event in events:
        if event.kind == "failure":
            failed_events += 1
            failures_by_ip[event.source_ip] += 1
            failures_by_user[event.username] += 1
            users_by_ip[event.source_ip].add(event.username)
            failures_since_success[event.source_ip] += 1
        else:
            successful_events += 1
            prior_failures = failures_since_success[event.source_ip]
            if prior_failures >= threshold:
                successes_after_failures.append(
                    SuccessAfterFailures(
                        source_ip=event.source_ip,
                        username=event.username,
                        timestamp=event.timestamp,
                        line_number=event.line_number,
                        preceding_failures=prior_failures,
                    )
                )
            failures_since_success[event.source_ip] = 0

    repeated_sources = [
        Finding(
            source_ip=source_ip,
            failed_attempts=count,
            usernames=sorted(users_by_ip[source_ip]),
        )
        for source_ip, count in failures_by_ip.most_common()
        if count >= threshold
    ]

    return Analysis(
        total_events=len(events),
        failed_events=failed_events,
        successful_events=successful_events,
        ignored_lines=max(0, total_lines - len(events)),
        failure_threshold=threshold,
        repeated_failure_sources=repeated_sources,
        successes_after_failures=successes_after_failures,
        failures_by_username=dict(failures_by_user.most_common()),
    )
