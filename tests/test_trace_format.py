"""Tests for trace serialization/deserialization roundtrip and text output."""

from __future__ import annotations

import pytest

from asgion.cli._output import format_trace_text
from asgion.trace import (
    TraceEnvironment,
    TraceEvent,
    TraceFormatError,
    TraceRecord,
    TraceScope,
    TraceSummary,
    TraceViolation,
)
from asgion.trace._format import (
    deserialize,
    extract_event_data,
    normalize_scope,
    serialize,
)


def _make_record(**overrides: object) -> TraceRecord:
    defaults = {
        "format_version": "1",
        "asgion_version": "0.5.0",
        "trace_id": "abc123",
        "recorded_at": "2026-02-24T00:00:00+00:00",
        "environment": TraceEnvironment(python="3.12.0", platform="linux-x86_64"),
        "scope": TraceScope(
            type="http",
            method="GET",
            path="/api",
            raw={"type": "http", "method": "GET", "path": "/api"},
        ),
        "events": (
            TraceEvent(
                t_ns=100,
                phase="receive",
                type="http.request",
                data={"body": "", "more_body": False},
            ),
            TraceEvent(
                t_ns=500,
                phase="send",
                type="http.response.start",
                data={"status": 200, "headers": []},
            ),
            TraceEvent(
                t_ns=800, phase="send", type="http.response.body", data={"body": "aGVsbG8="}
            ),
        ),
        "summary": TraceSummary(total_ns=1000, ttfb_ns=500, event_count=3, violations=()),
        "metadata": {},
    }
    defaults.update(overrides)
    return TraceRecord(**defaults)  # type: ignore[arg-type]


class TestSerializeDeserializeRoundtrip:
    def test_basic_roundtrip(self) -> None:
        record = _make_record()
        json_str = serialize(record)
        restored = deserialize(json_str)
        assert restored.format_version == record.format_version
        assert restored.trace_id == record.trace_id
        assert restored.scope.type == record.scope.type
        assert restored.scope.method == record.scope.method
        assert restored.scope.path == record.scope.path
        assert len(restored.events) == len(record.events)
        assert restored.summary.total_ns == record.summary.total_ns
        assert restored.summary.ttfb_ns == record.summary.ttfb_ns
        assert restored.summary.event_count == record.summary.event_count

    def test_metadata_preserved(self) -> None:
        record = _make_record(metadata={"source": "fuzz", "custom": 42})
        restored = deserialize(serialize(record))
        assert restored.metadata == {"source": "fuzz", "custom": 42}

    def test_empty_metadata_default(self) -> None:
        record = _make_record()
        restored = deserialize(serialize(record))
        assert restored.metadata == {}

    def test_violations_in_summary(self) -> None:
        violations = (
            TraceViolation(rule_id="G-001", phase="scope", event_index=None),
            TraceViolation(rule_id="HF-003", phase="send", event_index=0),
        )
        record = _make_record(
            summary=TraceSummary(total_ns=1000, ttfb_ns=None, event_count=0, violations=violations)
        )
        restored = deserialize(serialize(record))
        assert len(restored.summary.violations) == 2
        assert restored.summary.violations[0].rule_id == "G-001"
        assert restored.summary.violations[0].phase == "scope"
        assert restored.summary.violations[0].event_index is None
        assert restored.summary.violations[1].rule_id == "HF-003"
        assert restored.summary.violations[1].phase == "send"
        assert restored.summary.violations[1].event_index == 0
        assert restored.summary.ttfb_ns is None

    def test_websocket_scope(self) -> None:
        record = _make_record(
            scope=TraceScope(
                type="websocket", method="", path="/ws", raw={"type": "websocket", "path": "/ws"}
            ),
            events=(
                TraceEvent(t_ns=10, phase="receive", type="websocket.connect", data={}),
                TraceEvent(
                    t_ns=50, phase="send", type="websocket.accept", data={"subprotocol": None}
                ),
            ),
        )
        restored = deserialize(serialize(record))
        assert restored.scope.type == "websocket"
        assert restored.scope.method == ""
        assert restored.events[1].data["subprotocol"] is None


class TestDeserializeErrors:
    def test_unsupported_format_version(self) -> None:
        record = _make_record()
        json_str = serialize(record).replace('"format_version": "1"', '"format_version": "99"')
        with pytest.raises(TraceFormatError, match="99"):
            deserialize(json_str)

    def test_missing_format_version(self) -> None:
        with pytest.raises(TraceFormatError):
            deserialize('{"asgion_version": "0.5.0"}')


class TestNormalizeScope:
    def test_http_scope(self) -> None:
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/users",
            "headers": [(b"content-type", b"application/json")],
            "query_string": b"page=1",
            "raw_path": b"/api/users",
            "root_path": "",
        }
        ts = normalize_scope(scope)
        assert ts.type == "http"
        assert ts.method == "POST"
        assert ts.path == "/api/users"
        assert ts.raw["headers"] == [["content-type", "application/json"]]
        assert ts.raw["query_string"] == "page=1"
        assert "raw_path" not in ts.raw

    def test_lifespan_scope(self) -> None:
        scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
        ts = normalize_scope(scope)
        assert ts.type == "lifespan"
        assert ts.method == ""
        assert ts.path == ""


class TestExtractEventData:
    def test_http_response_start(self) -> None:
        msg = {"type": "http.response.start", "status": 200, "headers": [(b"x-foo", b"bar")]}
        data = extract_event_data(msg, max_body=65536)
        assert data["status"] == 200
        assert data["headers"] == [["x-foo", "bar"]]
        assert "type" not in data

    def test_body_base64(self) -> None:
        msg = {"type": "http.response.body", "body": b"hello", "more_body": False}
        data = extract_event_data(msg, max_body=65536)
        import base64

        assert base64.b64decode(data["body"]) == b"hello"
        assert data["more_body"] is False
        assert "body_truncated" not in data

    def test_body_truncation(self) -> None:
        msg = {"type": "http.response.body", "body": b"x" * 100, "more_body": False}
        data = extract_event_data(msg, max_body=10)
        import base64

        assert len(base64.b64decode(data["body"])) == 10
        assert data["body_truncated"] is True

    def test_ws_binary(self) -> None:
        msg = {"type": "websocket.send", "bytes": b"\x00\x01\x02"}
        data = extract_event_data(msg, max_body=65536)
        import base64

        assert base64.b64decode(data["bytes"]) == b"\x00\x01\x02"

    def test_ws_text(self) -> None:
        msg = {"type": "websocket.send", "text": "hello"}
        data = extract_event_data(msg, max_body=65536)
        assert data["text"] == "hello"

    def test_extension_fields_preserved(self) -> None:
        msg = {"type": "http.response.start", "status": 200, "headers": [], "x-custom": "value"}
        data = extract_event_data(msg, max_body=65536)
        assert data["x-custom"] == "value"

    def test_memoryview_body(self) -> None:
        body = memoryview(b"hello world")
        msg = {"type": "http.response.body", "body": body}
        data = extract_event_data(msg, max_body=65536)
        import base64

        assert base64.b64decode(data["body"]) == b"hello world"


# ---------------------------------------------------------------------------
# Text output formatting
# ---------------------------------------------------------------------------


class TestFormatTraceText:
    def test_http_trace_contains_method_path_status(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=True)
        assert "TRACE" in text
        assert "GET /api" in text
        assert "200" in text

    def test_http_trace_body_bytes(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=True)
        # body "aGVsbG8=" decodes to "hello" = 5 bytes
        assert "5 bytes" in text

    def test_http_trace_timing(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=True)
        assert "1µs" in text  # total_ns=1000
        assert "TTFB 0µs" in text  # ttfb_ns=500 -> <1µs

    def test_lifespan_trace_no_method_path(self) -> None:
        record = _make_record(
            scope=TraceScope(type="lifespan", method="", path="", raw={"type": "lifespan"}),
            events=(
                TraceEvent(t_ns=0, phase="receive", type="lifespan.startup", data={}),
                TraceEvent(t_ns=7000, phase="send", type="lifespan.startup.complete", data={}),
            ),
            summary=TraceSummary(total_ns=40000, ttfb_ns=None, event_count=2, violations=()),
        )
        text = format_trace_text([record], no_color=True)
        assert "lifespan" in text
        assert "GET" not in text
        assert "TTFB" not in text

    def test_websocket_trace_ws_prefix(self) -> None:
        record = _make_record(
            scope=TraceScope(
                type="websocket", method="", path="/ws", raw={"type": "websocket", "path": "/ws"}
            ),
            events=(
                TraceEvent(t_ns=10, phase="receive", type="websocket.connect", data={}),
                TraceEvent(
                    t_ns=50, phase="send", type="websocket.accept", data={"subprotocol": "graphql"}
                ),
            ),
            summary=TraceSummary(total_ns=100, ttfb_ns=None, event_count=2, violations=()),
        )
        text = format_trace_text([record], no_color=True)
        assert "WS /ws" in text
        assert "subprotocol=graphql" in text

    def test_violations_shown_inline(self) -> None:
        violations = (
            TraceViolation(rule_id="G-001", phase="scope", event_index=None),
            TraceViolation(rule_id="HF-003", phase="send", event_index=1),
        )
        record = _make_record(
            summary=TraceSummary(total_ns=1000, ttfb_ns=500, event_count=3, violations=violations)
        )
        text = format_trace_text([record], no_color=True)
        assert "Violations: 2" in text
        assert "scope: G-001" in text
        assert "\u2190 HF-003" in text

    def test_complete_violations_shown(self) -> None:
        violations = (TraceViolation(rule_id="HF-001", phase="complete", event_index=None),)
        record = _make_record(
            summary=TraceSummary(total_ns=1000, ttfb_ns=500, event_count=3, violations=violations)
        )
        text = format_trace_text([record], no_color=True)
        assert "complete: HF-001" in text

    def test_event_line_violation_marker(self) -> None:
        violations = (TraceViolation(rule_id="HF-002", phase="send", event_index=0),)
        record = _make_record(
            events=(
                TraceEvent(
                    t_ns=500,
                    phase="send",
                    type="http.response.start",
                    data={"status": 200, "headers": []},
                ),
            ),
            summary=TraceSummary(total_ns=1000, ttfb_ns=500, event_count=1, violations=violations),
        )
        text = format_trace_text([record], no_color=True)
        assert "\u2190 HF-002" in text
        # Event type should still be visible
        assert "http.response.start" in text

    def test_no_violations_clean_output(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=True)
        assert "scope:" not in text
        assert "complete:" not in text
        assert "\u2190" not in text

    def test_no_color_no_ansi(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=True)
        assert "\033[" not in text

    def test_color_has_ansi(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=False)
        assert "\033[" in text

    def test_multiple_records_separated(self) -> None:
        r1 = _make_record()
        r2 = _make_record(
            scope=TraceScope(type="lifespan", method="", path="", raw={"type": "lifespan"}),
            events=(),
            summary=TraceSummary(total_ns=100, ttfb_ns=None, event_count=0, violations=()),
        )
        text = format_trace_text([r1, r2], no_color=True)
        assert text.count("TRACE") == 2
        assert "───" in text

    def test_event_count_in_footer(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=True)
        assert "Events: 3" in text

    def test_content_type_in_response_start(self) -> None:
        record = _make_record(
            events=(
                TraceEvent(
                    t_ns=500,
                    phase="send",
                    type="http.response.start",
                    data={"status": 200, "headers": [["content-type", "application/json"]]},
                ),
            ),
            summary=TraceSummary(total_ns=1000, ttfb_ns=500, event_count=1, violations=()),
        )
        text = format_trace_text([record], no_color=True)
        assert "200 application/json" in text

    def test_delta_time_between_events(self) -> None:
        record = _make_record(
            events=(
                TraceEvent(
                    t_ns=100_000, phase="send", type="http.response.start", data={"status": 200}
                ),
                TraceEvent(
                    t_ns=300_000, phase="send", type="http.response.body", data={"body": "aGk="}
                ),
            ),
            summary=TraceSummary(total_ns=400_000, ttfb_ns=100_000, event_count=2, violations=()),
        )
        text = format_trace_text([record], no_color=True)
        # First event has no delta, second has +200µs
        assert "(+200µs)" in text

    def test_first_event_no_delta(self) -> None:
        record = _make_record(
            events=(TraceEvent(t_ns=100, phase="receive", type="http.request", data={}),),
            summary=TraceSummary(total_ns=200, ttfb_ns=None, event_count=1, violations=()),
        )
        text = format_trace_text([record], no_color=True)
        assert "(+" not in text

    def test_total_summary_for_multiple_records(self) -> None:
        r1 = _make_record(
            summary=TraceSummary(total_ns=1000, ttfb_ns=500, event_count=3, violations=()),
        )
        r2 = _make_record(
            scope=TraceScope(type="lifespan", method="", path="", raw={"type": "lifespan"}),
            events=(),
            summary=TraceSummary(total_ns=500, ttfb_ns=None, event_count=2, violations=()),
        )
        text = format_trace_text([r1, r2], no_color=True)
        assert "2 traces" in text
        assert "5 events" in text
        # No "violations" in summary when count is 0
        assert "violations" not in text.split("─ 2 traces")[1]

    def test_total_summary_shows_violations_when_present(self) -> None:
        r1 = _make_record(
            summary=TraceSummary(
                total_ns=1000,
                ttfb_ns=500,
                event_count=3,
                violations=(TraceViolation(rule_id="G-001", phase="scope", event_index=None),),
            ),
        )
        r2 = _make_record(
            scope=TraceScope(type="lifespan", method="", path="", raw={"type": "lifespan"}),
            events=(),
            summary=TraceSummary(
                total_ns=500,
                ttfb_ns=None,
                event_count=2,
                violations=(TraceViolation(rule_id="HF-003", phase="complete", event_index=None),),
            ),
        )
        text = format_trace_text([r1, r2], no_color=True)
        assert "2 violations" in text

    def test_no_total_summary_for_single_record(self) -> None:
        record = _make_record()
        text = format_trace_text([record], no_color=True)
        assert "traces" not in text
