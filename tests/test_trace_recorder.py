"""Tests for TraceRecorder."""

from __future__ import annotations

from asgion.trace import MemoryStorage, TraceRecord
from asgion.trace._recorder import TraceRecorder


def _make_recorder(
    scope: dict | None = None,
    max_body: int = 65536,
) -> tuple[TraceRecorder, MemoryStorage]:
    storage = MemoryStorage()
    if scope is None:
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "root_path": "",
        }
    recorder = TraceRecorder(scope, storage=storage, max_body=max_body, asgion_version="0.5.0-test")
    return recorder, storage


class TestTraceRecorder:
    def test_basic_http_lifecycle(self) -> None:
        recorder, storage = _make_recorder()
        recorder.on_receive({"type": "http.request", "body": b"", "more_body": False})
        recorder.on_send({"type": "http.response.start", "status": 200, "headers": []})
        recorder.on_send({"type": "http.response.body", "body": b"ok"})

        record = recorder.finalize([])

        assert isinstance(record, TraceRecord)
        assert record.format_version == "1"
        assert record.asgion_version == "0.5.0-test"
        assert record.scope.type == "http"
        assert record.scope.method == "GET"
        assert record.scope.path == "/"
        assert len(record.events) == 3
        assert record.events[0].phase == "receive"
        assert record.events[0].type == "http.request"
        assert record.events[1].phase == "send"
        assert record.events[1].type == "http.response.start"
        assert record.summary.event_count == 3
        assert record.summary.ttfb_ns is not None
        assert record.summary.total_ns > 0
        assert record.summary.violations == ()
        assert len(storage.records) == 1

    def test_ttfb_is_none_for_websocket(self) -> None:
        recorder, _ = _make_recorder(
            scope={
                "type": "websocket",
                "path": "/ws",
                "headers": [],
                "query_string": b"",
            }
        )
        recorder.on_receive({"type": "websocket.connect"})
        recorder.on_send({"type": "websocket.accept"})

        record = recorder.finalize([])
        assert record.summary.ttfb_ns is None

    def test_violations_recorded(self) -> None:
        from asgion.core._types import Severity
        from asgion.core.violation import Violation

        recorder, _ = _make_recorder()
        recorder.on_receive({"type": "http.request", "body": b""})
        violations = [
            Violation(rule_id="G-001", severity=Severity.ERROR, message="test"),
            Violation(rule_id="HF-002", severity=Severity.WARNING, message="test2"),
        ]
        tags = [("scope", None), ("send", 0)]
        record = recorder.finalize(violations, tags)
        assert len(record.summary.violations) == 2
        assert record.summary.violations[0].rule_id == "G-001"
        assert record.summary.violations[0].phase == "scope"
        assert record.summary.violations[0].event_index is None
        assert record.summary.violations[1].rule_id == "HF-002"
        assert record.summary.violations[1].phase == "send"
        assert record.summary.violations[1].event_index == 0

    def test_violations_without_tags_fallback(self) -> None:
        from asgion.core._types import Severity
        from asgion.core.violation import Violation

        recorder, _ = _make_recorder()
        record = recorder.finalize(
            [Violation(rule_id="G-001", severity=Severity.ERROR, message="test")]
        )
        assert record.summary.violations[0].phase == "unknown"
        assert record.summary.violations[0].event_index is None

    def test_event_count_property(self) -> None:
        recorder, _ = _make_recorder()
        assert recorder.event_count == 0
        recorder.on_receive({"type": "http.request", "body": b""})
        assert recorder.event_count == 1
        recorder.on_send({"type": "http.response.start", "status": 200, "headers": []})
        assert recorder.event_count == 2

    def test_trace_id_is_unique(self) -> None:
        ids = set()
        for _ in range(10):
            recorder, _ = _make_recorder()
            record = recorder.finalize([])
            ids.add(record.trace_id)
        assert len(ids) == 10

    def test_events_timestamps_monotonic(self) -> None:
        recorder, _ = _make_recorder()
        recorder.on_receive({"type": "http.request", "body": b""})
        recorder.on_send({"type": "http.response.start", "status": 200, "headers": []})
        recorder.on_send({"type": "http.response.body", "body": b"x"})

        record = recorder.finalize([])
        timestamps = [e.t_ns for e in record.events]
        assert timestamps == sorted(timestamps)

    def test_shallow_copy_isolation(self) -> None:
        recorder, _ = _make_recorder()
        msg = {"type": "http.request", "body": b"original"}
        recorder.on_receive(msg)
        msg["body"] = b"mutated"

        record = recorder.finalize([])
        import base64

        body = base64.b64decode(record.events[0].data["body"])
        assert body == b"original"

    def test_metadata_is_empty_dict(self) -> None:
        recorder, _ = _make_recorder()
        record = recorder.finalize([])
        assert record.metadata == {}

    def test_environment_populated(self) -> None:
        recorder, _ = _make_recorder()
        record = recorder.finalize([])
        assert record.environment.python
        assert record.environment.platform
