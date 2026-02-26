"""Integration tests for Inspector with trace=True."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from asgion.core.inspector import Inspector
from asgion.trace import MemoryStorage, TraceRecord, TraceViolation
from asgion.trace._format import deserialize, serialize

if TYPE_CHECKING:
    from pathlib import Path

    from asgion.core._types import ASGIApp, Message, Receive, Scope, Send


def _make_http_app(status: int = 200, body: bytes = b"ok") -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
                msg = await receive()
            if msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
            return
        await receive()
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": body})

    return app


def _make_ws_app() -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        msg = await receive()
        assert msg["type"] == "websocket.connect"
        await send({"type": "websocket.accept"})
        msg = await receive()
        if msg["type"] == "websocket.receive":
            await send({"type": "websocket.send", "text": "echo"})
            msg = await receive()
        await send({"type": "websocket.close", "code": 1000})

    return app


async def _drive_http(inspector: Inspector, path: str = "/", method: str = "GET") -> None:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    responses: list[dict[str, Any]] = []

    async def send(message: Message) -> None:
        responses.append(message)

    await inspector(scope, receive, send)


async def _drive_ws(inspector: Inspector, path: str = "/ws") -> None:
    scope: Scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "subprotocols": [],
    }
    phase = "connect"

    async def receive() -> Message:
        nonlocal phase
        if phase == "connect":
            phase = "connected"
            return {"type": "websocket.connect"}
        if phase == "connected":
            phase = "disconnect"
            return {"type": "websocket.receive", "text": "hello"}
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Message) -> None:
        pass

    await inspector(scope, receive, send)


class TestInspectorTraceBasic:
    async def test_trace_false_no_traces_attr(self) -> None:
        inspector = Inspector(_make_http_app())
        with pytest.raises(AttributeError, match="trace=False"):
            _ = inspector.traces

    async def test_trace_true_returns_traces(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True)
        await _drive_http(inspector)
        assert len(inspector.traces) == 1
        record = inspector.traces[0]
        assert isinstance(record, TraceRecord)
        assert record.scope.type == "http"
        assert record.scope.method == "GET"
        assert record.scope.path == "/"

    async def test_multiple_requests(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True)
        await _drive_http(inspector, path="/a")
        await _drive_http(inspector, path="/b", method="POST")
        assert len(inspector.traces) == 2
        assert inspector.traces[0].scope.path == "/a"
        assert inspector.traces[1].scope.path == "/b"
        assert inspector.traces[1].scope.method == "POST"

    async def test_trace_events_recorded(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True)
        await _drive_http(inspector)
        record = inspector.traces[0]
        types = [e.type for e in record.events]
        assert "http.request" in types
        assert "http.response.start" in types
        assert "http.response.body" in types

    async def test_trace_ttfb(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True)
        await _drive_http(inspector)
        record = inspector.traces[0]
        assert record.summary.ttfb_ns is not None
        assert record.summary.ttfb_ns > 0

    async def test_trace_event_count(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True)
        await _drive_http(inspector)
        record = inspector.traces[0]
        assert record.summary.event_count == len(record.events)

    async def test_violations_still_collected(self) -> None:
        async def bad_app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] != "http":
                return
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.start", "status": 200, "headers": []})

        inspector = Inspector(bad_app, trace=True)
        await _drive_http(inspector)
        assert len(inspector.violations) > 0
        assert len(inspector.traces) == 1
        violations = inspector.traces[0].summary.violations
        assert len(violations) > 0
        for v in violations:
            assert isinstance(v, TraceViolation)
            assert v.rule_id
            assert v.phase in ("scope", "receive", "send", "complete")

    async def test_violation_phase_tracking(self) -> None:
        async def bad_app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] != "http":
                return
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.start", "status": 200, "headers": []})

        inspector = Inspector(bad_app, trace=True)
        await _drive_http(inspector)
        violations = inspector.traces[0].summary.violations
        # At least one violation should be on a send event
        send_violations = [v for v in violations if v.phase == "send"]
        assert len(send_violations) > 0
        for sv in send_violations:
            assert sv.event_index is not None
            assert sv.event_index >= 0


class TestInspectorTraceWebSocket:
    async def test_ws_trace(self) -> None:
        inspector = Inspector(_make_ws_app(), trace=True)
        await _drive_ws(inspector)
        assert len(inspector.traces) == 1
        record = inspector.traces[0]
        assert record.scope.type == "websocket"
        assert record.summary.ttfb_ns is None


class TestInspectorTraceSampling:
    async def test_sample_rate_0_no_traces(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True, sample_rate=0.0)
        await _drive_http(inspector)
        assert len(inspector.traces) == 0

    async def test_sample_rate_1_all_traced(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True, sample_rate=1.0)
        for i in range(5):
            await _drive_http(inspector, path=f"/p{i}")
        assert len(inspector.traces) == 5


class TestInspectorTraceStorage:
    async def test_custom_storage(self) -> None:
        storage = MemoryStorage()
        inspector = Inspector(_make_http_app(), trace=True, storage=storage)
        await _drive_http(inspector)
        assert len(storage.records) == 1
        assert len(inspector.traces) == 1
        assert inspector.traces[0] is storage.records[0]

    async def test_file_storage(self, tmp_path: Path) -> None:
        inspector = Inspector(_make_http_app(), trace=True, trace_dir=tmp_path / "traces")
        await _drive_http(inspector)
        files = list((tmp_path / "traces").glob("*.json"))
        assert len(files) == 1
        restored = deserialize(files[0].read_text(encoding="utf-8"))
        assert restored.scope.method == "GET"

    async def test_storage_and_trace_dir_conflict(self, tmp_path: Path) -> None:
        with pytest.raises(TypeError, match="Cannot specify both"):
            Inspector(
                _make_http_app(),
                trace=True,
                storage=MemoryStorage(),
                trace_dir=tmp_path / "traces",
            )


class TestInspectorTraceRoundtrip:
    async def test_serialize_roundtrip(self) -> None:
        inspector = Inspector(_make_http_app(body=b"hello world"), trace=True)
        await _drive_http(inspector)
        record = inspector.traces[0]
        json_str = serialize(record)
        restored = deserialize(json_str)
        assert restored.trace_id == record.trace_id
        assert restored.scope.method == record.scope.method
        assert len(restored.events) == len(record.events)
        assert restored.summary.total_ns == record.summary.total_ns


class TestInspectorTraceExcludePaths:
    async def test_excluded_path_not_traced(self) -> None:
        inspector = Inspector(_make_http_app(), trace=True, exclude_paths=["/health"])
        await _drive_http(inspector, path="/health")
        await _drive_http(inspector, path="/api")
        assert len(inspector.traces) == 1
        assert inspector.traces[0].scope.path == "/api"
