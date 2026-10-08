"""Parse common JSON event, JSON array, envelope, and JSON Lines formats."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .parser import AuthEvent, EventKind, normalize_ip, parse_line, parse_message

_ENVELOPE_KEYS = ("events", "logs", "records", "items", "results")
_MESSAGE_FIELDS = ("message", "msg", "log", "event.original", "event", "MESSAGE")
_IP_FIELDS = (
    "source.ip",
    "source_ip",
    "src_ip",
    "client.ip",
    "client_ip",
    "remote_ip",
    "remote.address",
    "remote_addr",
    "source.address",
    "ip",
)
_USER_FIELDS = ("user.name", "username", "user_name", "user", "account", "target.user.name")
_TIME_FIELDS = ("@timestamp", "timestamp", "time", "datetime", "event.created")
_HOST_FIELDS = ("host.name", "hostname", "_HOSTNAME", "host")
_STATUS_FIELDS = (
    "event.outcome",
    "outcome",
    "auth_result",
    "authentication.result",
    "status",
    "result",
    "event.action",
    "action",
    "event.type",
    "type",
)


def _lookup(record: Mapping[str, Any], path: str) -> Any:
    """Find a nested dotted field or a literal key containing dots."""
    if path in record:
        return record[path]
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _ordered_fields(
    key: str,
    defaults: tuple[str, ...],
    field_map: Mapping[str, str] | None,
) -> tuple[str, ...]:
    custom = field_map.get(key) if field_map else None
    return ((custom,) if custom else ()) + defaults


def _first_string(
    record: Mapping[str, Any],
    fields: tuple[str, ...],
    field_map: Mapping[str, str] | None = None,
    map_key: str | None = None,
) -> str | None:
    if map_key:
        fields = _ordered_fields(map_key, fields, field_map)
    for field in fields:
        value = _lookup(record, field)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return str(value)
    return None


def _records(document: Any, depth: int = 0) -> list[Any]:
    """Unwrap common API envelopes and Elasticsearch-style hits."""
    if depth > 8:
        return []
    if isinstance(document, list):
        records = []
        for item in document:
            if isinstance(item, Mapping) and isinstance(item.get("_source"), Mapping):
                records.extend(_records(item["_source"], depth + 1))
            else:
                records.extend(_records(item, depth + 1))
        return records
    if not isinstance(document, Mapping):
        return [document]

    hits = _lookup(document, "hits.hits")
    if isinstance(hits, list):
        return _records(hits, depth + 1)

    for key in _ENVELOPE_KEYS:
        if key in document and isinstance(document[key], (list, Mapping)):
            return _records(document[key], depth + 1)

    data = document.get("data")
    if isinstance(data, (list, Mapping)) and (
        isinstance(data, list)
        or any(key in data for key in (*_ENVELOPE_KEYS, "hits", "_source"))
    ):
        return _records(data, depth + 1)

    if isinstance(document.get("_source"), Mapping):
        return _records(document["_source"], depth + 1)
    return [document]


def _event_kind(record: Mapping[str, Any], field_map: Mapping[str, str] | None) -> EventKind | None:
    for field in _ordered_fields("status", _STATUS_FIELDS, field_map):
        value = _lookup(record, field)
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        if any(word in normalized for word in ("failure", "failed", "denied", "rejected", "invalid_password")):
            return "failure"
        if any(word in normalized for word in ("success", "accepted", "authenticated", "login_ok")):
            return "success"
    return None


def _parse_record(
    record: Any,
    record_number: int,
    field_map: Mapping[str, str] | None = None,
) -> AuthEvent | None:
    if not isinstance(record, Mapping):
        return None

    timestamp = _first_string(record, _TIME_FIELDS, field_map, "time") or ""
    host = _first_string(record, _HOST_FIELDS, field_map, "host") or ""

    for field in _ordered_fields("message", _MESSAGE_FIELDS, field_map):
        message = _lookup(record, field)
        if not isinstance(message, str):
            continue
        # JSON loggers often preserve the whole original syslog line.
        event = parse_line(message, record_number)
        if event is not None:
            return event
        event = parse_message(message, record_number, timestamp=timestamp, host=host)
        if event is not None:
            return event

    kind = _event_kind(record, field_map)
    if kind is None:
        return None

    raw_ip = _first_string(record, _IP_FIELDS, field_map, "ip")
    source_ip = normalize_ip(raw_ip) if raw_ip else None
    if source_ip is None:
        return None

    username = _first_string(record, _USER_FIELDS, field_map, "user") or "unknown"
    return AuthEvent(
        line_number=record_number,
        timestamp=timestamp,
        host=host,
        kind=kind,
        username=username,
        source_ip=source_ip,
    )


def parse_json_document(
    text: str,
    field_map: Mapping[str, str] | None = None,
) -> tuple[list[AuthEvent], int]:
    """Parse a JSON document containing a record, list, or common envelope."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {error.msg} at line {error.lineno}") from error
    records = _records(document)
    events = [
        event
        for index, record in enumerate(records, start=1)
        if (event := _parse_record(record, index, field_map))
    ]
    return events, len(records)


def parse_json_lines(
    text: str,
    field_map: Mapping[str, str] | None = None,
) -> tuple[list[AuthEvent], int]:
    """Parse newline-delimited JSON objects, counting invalid rows as ignored."""
    records: list[Any] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append(None)
    events = [
        event
        for index, record in enumerate(records, start=1)
        if (event := _parse_record(record, index, field_map))
    ]
    return events, len(records)


def parse_content(
    text: str,
    format_name: str = "auto",
    field_map: Mapping[str, str] | None = None,
) -> tuple[list[AuthEvent], int]:
    """Parse text, JSON, or JSON Lines; auto-detect structured JSON when possible."""
    if format_name == "text":
        lines = text.splitlines()
        return [event for event in (parse_line(line, i) for i, line in enumerate(lines, 1)) if event], len(lines)
    if format_name == "json":
        return parse_json_document(text, field_map)
    if format_name == "jsonl":
        return parse_json_lines(text, field_map)
    if format_name != "auto":
        raise ValueError(f"unsupported input format: {format_name}")

    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            return parse_json_document(text, field_map)
        except ValueError:
            events, records = parse_json_lines(text, field_map)
            valid_json_lines = 0
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    json.loads(line)
                    valid_json_lines += 1
                except json.JSONDecodeError:
                    pass
            if valid_json_lines:
                return events, recordss
            raise
    return parse_content(text, "text", field_map)
