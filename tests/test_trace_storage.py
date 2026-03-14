"""Tests for trace storage backends."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from asgion.trace import (
    MemoryStorage,
    TraceEnvironment,
    TraceEvent,
    TraceRecord,
    TraceScope,
    TraceSummary,
)
from asgion.trace._format import deserialize
from asgion.trace._storage import FileStorage, _make_filename

if TYPE_CHECKING:
    from pathlib import Path


def _make_record(**overrides: object) -> TraceRecord:
    defaults = {
        "format_version": "1",
        "asgion_version": "0.5.0",
        "trace_id": "abcdef123456",
        "recorded_at": "2026-02-24T00:00:00+00:00",
        "environment": TraceEnvironment(python="3.12.0", platform="linux-x86_64"),
        "scope": TraceScope(type="http", method="GET", path="/api", raw={}),
        "events": (),
        "summary": TraceSummary(total_ns=1000, ttfb_ns=500, event_count=0, violations=()),
        "metadata": {},
    }
    defaults.update(overrides)
    return TraceRecord(**defaults)  # type: ignore[arg-type]


class TestMemoryStorage:
    def test_store_and_retrieve(self) -> None:
        storage = MemoryStorage()
        record = _make_record()
        storage.store(record)
        assert len(storage.records) == 1
        assert storage.records[0] is record

    def test_multiple_records(self) -> None:
        storage = MemoryStorage()
        for i in range(5):
            storage.store(_make_record(trace_id=f"id-{i}"))
        assert len(storage.records) == 5


class TestFileStorage:
    def test_store_creates_file(self, tmp_path: Path) -> None:
        storage = FileStorage(tmp_path / "traces")
        record = _make_record()
        storage.store(record)
        files = list((tmp_path / "traces").glob("*.json"))
        assert len(files) == 1

    def test_stored_file_deserializable(self, tmp_path: Path) -> None:
        storage = FileStorage(tmp_path / "traces")
        record = _make_record(
            events=(TraceEvent(t_ns=100, phase="receive", type="http.request", data={}),),
        )
        storage.store(record)
        files = list((tmp_path / "traces").glob("*.json"))
        restored = deserialize(files[0].read_text(encoding="utf-8"))
        assert restored.trace_id == record.trace_id
        assert restored.scope.method == "GET"

    def test_creates_directory(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "a" / "b" / "c"
        storage = FileStorage(deep_path)
        storage.store(_make_record())
        assert deep_path.exists()

    def test_rejects_readonly_directory(self, tmp_path: Path) -> None:
        readonly = tmp_path / "readonly"
        readonly.mkdir()
        readonly.chmod(0o444)
        try:
            with pytest.raises(PermissionError, match="not writable"):
                FileStorage(readonly)
        finally:
            readonly.chmod(0o755)


class TestMakeFilename:
    def test_http_filename(self) -> None:
        record = _make_record(trace_id="aabbccdd1234")
        name = _make_filename(record)
        assert name == "aabbccdd1234_get_api.json"

    def test_root_path(self) -> None:
        record = _make_record(
            trace_id="aabbccdd1234",
            scope=TraceScope(type="http", method="POST", path="/", raw={}),
        )
        name = _make_filename(record)
        assert name == "aabbccdd1234_post_root.json"

    def test_websocket(self) -> None:
        record = _make_record(
            trace_id="aabbccdd1234",
            scope=TraceScope(type="websocket", method="", path="/ws/chat", raw={}),
        )
        name = _make_filename(record)
        assert name == "aabbccdd1234_websocket_ws_chat.json"

    def test_lifespan(self) -> None:
        record = _make_record(
            trace_id="aabbccdd1234",
            scope=TraceScope(type="lifespan", method="", path="", raw={}),
        )
        name = _make_filename(record)
        assert name == "aabbccdd1234_lifespan_root.json"
