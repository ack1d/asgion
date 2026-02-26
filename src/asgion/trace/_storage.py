from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from asgion.trace import TraceRecord


class MemoryStorage:
    """In-memory trace storage for dev/test use."""

    def __init__(self) -> None:
        self._records: list[TraceRecord] = []

    def store(self, record: TraceRecord) -> None:
        self._records.append(record)

    @property
    def records(self) -> list[TraceRecord]:
        return self._records


def _make_filename(record: TraceRecord) -> str:
    scope = record.scope
    method = scope.method.lower() if scope.method else scope.type
    path = scope.path.strip("/").replace("/", "_") or "root"
    return f"{record.trace_id[:12]}_{method}_{path}.json"


class FileStorage:
    """File-based trace storage. Writes one JSON file per trace."""

    def __init__(self, trace_dir: Path) -> None:
        self._trace_dir = trace_dir
        self._trace_dir.mkdir(parents=True, exist_ok=True)

    def store(self, record: TraceRecord) -> None:
        from asgion.trace._format import serialize

        path = self._trace_dir / _make_filename(record)
        path.write_text(serialize(record), encoding="utf-8")
