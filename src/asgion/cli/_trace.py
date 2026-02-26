"""CLI ``asgion trace`` command — record ASGI lifecycle traces."""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

from asgion.cli._runner import _TIMEOUT, _parse_path
from asgion.core.inspector import Inspector

if TYPE_CHECKING:
    from pathlib import Path

    from asgion.core._types import Message, Scope
    from asgion.trace import TraceRecord


async def _trace_lifespan(inspector: Inspector) -> None:
    scope: Scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
    phase = "startup"

    async def receive() -> Message:
        nonlocal phase
        if phase == "startup":
            phase = "started"
            return {"type": "lifespan.startup"}
        if phase == "shutdown":
            phase = "done"
            return {"type": "lifespan.shutdown"}
        await asyncio.sleep(999)
        return {"type": "lifespan.shutdown"}

    async def send(message: Message) -> None:
        nonlocal phase
        msg_type = message.get("type", "")
        if msg_type in ("lifespan.startup.complete", "lifespan.startup.failed"):
            phase = "shutdown"

    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(inspector(scope, receive, send), timeout=_TIMEOUT)


async def _trace_ws(inspector: Inspector, *, path: str = "/ws") -> None:
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
        if phase == "message":
            phase = "disconnect"
            return {"type": "websocket.receive", "text": ""}
        if phase == "disconnect":
            phase = "done"
            return {"type": "websocket.disconnect", "code": 1000}
        await asyncio.sleep(999)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Message) -> None:
        nonlocal phase
        msg_type = message.get("type", "")
        if msg_type == "websocket.accept" and phase == "connected":
            phase = "message"
        elif msg_type == "websocket.close":
            phase = "done"

    with contextlib.suppress(TimeoutError, Exception):
        await asyncio.wait_for(inspector(scope, receive, send), timeout=_TIMEOUT)


async def _trace_http(inspector: Inspector, *, path: str = "/", method: str = "GET") -> None:
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
    request_sent = False

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(999)
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        pass

    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(inspector(scope, receive, send), timeout=_TIMEOUT)


def run_trace(
    app: object,
    *,
    paths: tuple[str, ...] = ("/",),
    trace_dir: str | Path | None = None,
    max_body_size: int = 64 * 1024,
    run_lifespan: bool = True,
) -> list[TraceRecord]:
    """Run ASGI app with tracing and return recorded traces."""

    inspector = Inspector(
        app,  # type: ignore[arg-type]
        trace=True,
        trace_dir=trace_dir,
        max_body_size=max_body_size,
    )

    async def _run() -> None:
        if run_lifespan:
            await _trace_lifespan(inspector)
        for raw in paths:
            scope_type, path = _parse_path(raw)
            if scope_type == "websocket":
                await _trace_ws(inspector, path=path)
            else:
                await _trace_http(inspector, path=path)

    asyncio.run(_run())
    return inspector.traces
