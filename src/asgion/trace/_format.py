from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

from asgion.trace import (
    TraceEnvironment,
    TraceEvent,
    TraceFormatError,
    TraceRecord,
    TraceScope,
    TraceSummary,
    TraceViolation,
)

if TYPE_CHECKING:
    from asgion.core._types import Message, Scope

_FORMAT_VERSION = "1"


def _latin1(value: bytes) -> str:
    return value.decode("latin-1")


def normalize_scope(scope: Scope) -> TraceScope:
    """Build a TraceScope from an ASGI scope dict.

    Captures scope at connection creation time. Mutations to ``scope["state"]``
    during the connection are NOT reflected — trace records initial state only.
    """
    # Keys that are never useful in traces: app is the ASGI callable,
    # state is a mutable dict-like set by middleware at runtime.
    skip_keys = {"raw_path", "app", "state"}

    raw: dict[str, Any] = {}
    for key, value in scope.items():
        if key in skip_keys:
            continue
        if key == "headers":
            raw["headers"] = [[_latin1(k), _latin1(v)] for k, v in value]
        elif key == "query_string":
            raw["query_string"] = _latin1(value) if isinstance(value, bytes) else value
        elif isinstance(value, bytes):
            raw[key] = _latin1(value)
        elif isinstance(value, (str, int, float, bool, list, dict, type(None))):
            raw[key] = value
    return TraceScope(
        type=scope.get("type", "unknown"),
        method=scope.get("method", ""),
        path=scope.get("path", ""),
        raw=raw,
    )


def _encode_body(raw: bytes | bytearray | memoryview, max_body: int) -> dict[str, Any]:
    raw_bytes = bytes(raw)
    encoded = base64.b64encode(raw_bytes[:max_body]).decode("ascii")
    if len(raw_bytes) > max_body:
        return {"body": encoded, "body_truncated": True}
    return {"body": encoded}


def extract_event_data(message: Message, max_body: int) -> dict[str, Any]:
    """Extract all fields from an ASGI message except ``type``.

    All message fields are preserved for future replay (FC-1).
    Binary fields are normalized: bytes -> base64, headers -> list[list[str]].
    """
    data: dict[str, Any] = {}
    for key, value in message.items():
        if key == "type":
            continue
        if key == "body" and isinstance(value, (bytes, bytearray, memoryview)):
            data.update(_encode_body(value, max_body))
        elif key == "bytes" and isinstance(value, (bytes, bytearray, memoryview)):
            data["bytes"] = base64.b64encode(bytes(value)).decode("ascii")
        elif key == "headers" and isinstance(value, list):
            data["headers"] = [[_latin1(k), _latin1(v)] for k, v in value]
        elif isinstance(value, bytes):
            data[key] = _latin1(value)
        else:
            data[key] = value
    return data


def _event_to_dict(event: TraceEvent) -> dict[str, Any]:
    return {
        "t_ns": event.t_ns,
        "phase": event.phase,
        "type": event.type,
        "data": event.data,
    }


def _record_to_dict(record: TraceRecord) -> dict[str, Any]:
    return {
        "format_version": record.format_version,
        "asgion_version": record.asgion_version,
        "trace_id": record.trace_id,
        "recorded_at": record.recorded_at,
        "environment": {
            "python": record.environment.python,
            "platform": record.environment.platform,
        },
        "scope": {
            "type": record.scope.type,
            "method": record.scope.method,
            "path": record.scope.path,
            "raw": record.scope.raw,
        },
        "events": [_event_to_dict(e) for e in record.events],
        "summary": {
            "total_ns": record.summary.total_ns,
            "ttfb_ns": record.summary.ttfb_ns,
            "event_count": record.summary.event_count,
            "violations": [
                {
                    "rule_id": v.rule_id,
                    "phase": v.phase,
                    "event_index": v.event_index,
                }
                for v in record.summary.violations
            ],
        },
        "metadata": record.metadata,
    }


def serialize(record: TraceRecord) -> str:
    """Serialize a TraceRecord to JSON string."""
    return json.dumps(_record_to_dict(record), ensure_ascii=False, indent=2)


def _dict_to_event(d: dict[str, Any]) -> TraceEvent:
    return TraceEvent(
        t_ns=d["t_ns"],
        phase=d["phase"],
        type=d["type"],
        data=d.get("data", {}),
    )


def _deserialize_violations(raw: list[Any]) -> tuple[TraceViolation, ...]:
    result: list[TraceViolation] = []
    for item in raw:
        if isinstance(item, str):
            result.append(TraceViolation(rule_id=item, phase="unknown", event_index=None))
        else:
            result.append(
                TraceViolation(
                    rule_id=item["rule_id"],
                    phase=item.get("phase", "unknown"),
                    event_index=item.get("event_index"),
                )
            )
    return tuple(result)


def _dict_to_record(d: dict[str, Any]) -> TraceRecord:
    env = d["environment"]
    scope = d["scope"]
    summary = d["summary"]
    return TraceRecord(
        format_version=d["format_version"],
        asgion_version=d["asgion_version"],
        trace_id=d["trace_id"],
        recorded_at=d["recorded_at"],
        environment=TraceEnvironment(
            python=env["python"],
            platform=env["platform"],
        ),
        scope=TraceScope(
            type=scope["type"],
            method=scope.get("method", ""),
            path=scope.get("path", ""),
            raw=scope.get("raw", {}),
        ),
        events=tuple(_dict_to_event(e) for e in d.get("events", [])),
        summary=TraceSummary(
            total_ns=summary["total_ns"],
            ttfb_ns=summary.get("ttfb_ns"),
            event_count=summary.get("event_count", 0),
            violations=_deserialize_violations(summary.get("violations", ())),
        ),
        metadata=d.get("metadata", {}),
    )


def deserialize(data: str) -> TraceRecord:
    """Deserialize a JSON string to TraceRecord.

    Unknown fields are silently ignored for forward compatibility.
    """
    d = json.loads(data)
    version = d.get("format_version", "")
    if version != _FORMAT_VERSION:
        msg = f"Unsupported trace format version: {version!r}. Expected {_FORMAT_VERSION!r}."
        raise TraceFormatError(msg)
    return _dict_to_record(d)
