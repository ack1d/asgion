from __future__ import annotations

import platform
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from asgion.trace import (
    TraceEnvironment,
    TraceEvent,
    TraceRecord,
    TraceSummary,
    TraceViolation,
)
from asgion.trace._format import _FORMAT_VERSION, extract_event_data, normalize_scope

if TYPE_CHECKING:
    from asgion.core._types import Message, Scope
    from asgion.core.violation import Violation
    from asgion.trace import TraceStorage


class TraceRecorder:
    """Records ASGI events during a single connection lifecycle.

    Hot path (on_receive/on_send): O(1) per message — only perf_counter_ns() +
    list.append(tuple). Heavy processing (base64, normalization) is deferred
    to finalize().
    """

    __slots__ = ("_asgion_version", "_max_body", "_raw_events", "_scope", "_start_ns", "_storage")

    def __init__(
        self,
        scope: Scope,
        *,
        storage: TraceStorage,
        max_body: int,
        asgion_version: str,
    ) -> None:
        self._scope = scope
        self._raw_events: list[tuple[int, str, str, dict[str, Any]]] = []
        self._start_ns = time.perf_counter_ns()
        self._max_body = max_body
        self._storage = storage
        self._asgion_version = asgion_version

    @property
    def event_count(self) -> int:
        return len(self._raw_events)

    def on_receive(self, message: Message) -> None:
        t = time.perf_counter_ns() - self._start_ns
        msg_type = message.get("type", "")
        self._raw_events.append((t, "receive", msg_type, dict(message)))

    def on_send(self, message: Message) -> None:
        t = time.perf_counter_ns() - self._start_ns
        msg_type = message.get("type", "")
        self._raw_events.append((t, "send", msg_type, dict(message)))

    def finalize(
        self,
        violations: list[Violation],
        violation_tags: list[tuple[str, int | None]] | None = None,
    ) -> TraceRecord:
        """Build the final TraceRecord and store it.

        Called once at connection end (in ``finally``). Performs all heavy
        processing: base64 encoding, header normalization, JSON-safe conversion.
        """
        total_ns = time.perf_counter_ns() - self._start_ns

        events: list[TraceEvent] = []
        ttfb_ns: int | None = None

        for t_ns, phase, msg_type, message in self._raw_events:
            data = extract_event_data(message, self._max_body)
            events.append(TraceEvent(t_ns=t_ns, phase=phase, type=msg_type, data=data))
            if ttfb_ns is None and msg_type == "http.response.start":
                ttfb_ns = t_ns

        if violation_tags is not None:
            trace_violations = tuple(
                TraceViolation(rule_id=v.rule_id, phase=phase, event_index=idx)
                for v, (phase, idx) in zip(violations, violation_tags, strict=True)
            )
        else:
            trace_violations = tuple(
                TraceViolation(rule_id=v.rule_id, phase="unknown", event_index=None)
                for v in violations
            )

        record = TraceRecord(
            format_version=_FORMAT_VERSION,
            asgion_version=self._asgion_version,
            trace_id=uuid4().hex,
            recorded_at=datetime.now(UTC).isoformat(),
            environment=_get_environment(),
            scope=normalize_scope(self._scope),
            events=tuple(events),
            summary=TraceSummary(
                total_ns=total_ns,
                ttfb_ns=ttfb_ns,
                event_count=len(events),
                violations=trace_violations,
            ),
        )
        self._storage.store(record)
        return record


def _build_environment() -> TraceEnvironment:
    import sys

    return TraceEnvironment(
        python=platform.python_version(),
        platform=f"{sys.platform}-{platform.machine()}",
    )


_cached_env: TraceEnvironment | None = None


def _get_environment() -> TraceEnvironment:
    global _cached_env  # noqa: PLW0603
    if _cached_env is None:
        _cached_env = _build_environment()
    return _cached_env
