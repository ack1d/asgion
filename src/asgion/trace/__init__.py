"""ASGI lifecycle trace recording and storage."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from asgion.trace._storage import FileStorage, MemoryStorage

__all__ = [
    "FileStorage",
    "MemoryStorage",
    "TraceEnvironment",
    "TraceEvent",
    "TraceFormatError",
    "TraceRecord",
    "TraceScope",
    "TraceStorage",
    "TraceSummary",
    "TraceViolation",
]


class TraceFormatError(Exception):
    """Raised when a trace file has an unsupported or invalid format."""


@runtime_checkable
class TraceStorage(Protocol):
    """Public protocol for trace storage backends.

    Implement this to create custom storage (OTel exporter, database, etc.)::

        class OTelStorage:
            def store(self, record: TraceRecord) -> None:
                export_to_otel(record)

        inspector = Inspector(app, trace=True, storage=OTelStorage())
    """

    def store(self, record: TraceRecord) -> None: ...


@dataclass(frozen=True, slots=True)
class TraceEvent:
    t_ns: int
    phase: str
    type: str
    data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TraceEnvironment:
    python: str
    platform: str


@dataclass(frozen=True, slots=True)
class TraceScope:
    type: str
    method: str
    path: str
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TraceViolation:
    rule_id: str
    phase: str
    event_index: int | None


@dataclass(frozen=True, slots=True)
class TraceSummary:
    total_ns: int
    ttfb_ns: int | None
    event_count: int
    violations: tuple[TraceViolation, ...]


@dataclass(frozen=True, slots=True)
class TraceRecord:
    format_version: str
    asgion_version: str
    trace_id: str
    recorded_at: str
    environment: TraceEnvironment
    scope: TraceScope
    events: tuple[TraceEvent, ...]
    summary: TraceSummary
    metadata: dict[str, Any] = field(default_factory=dict)
