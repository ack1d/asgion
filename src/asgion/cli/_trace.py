"""CLI ``asgion trace`` command — record ASGI lifecycle traces."""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import click

from asgion.cli._runner import _TIMEOUT, _parse_path
from asgion.cli._sessions import http_session, lifespan_session, ws_session
from asgion.core.inspector import Inspector

if TYPE_CHECKING:
    from pathlib import Path

    from asgion.trace import TraceRecord


async def _trace_lifespan(inspector: Inspector) -> None:
    scope, receive, send = lifespan_session()
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(inspector(scope, receive, send), timeout=_TIMEOUT)


async def _trace_ws(inspector: Inspector, *, path: str = "/ws") -> None:
    scope, receive, send = ws_session(path=path)
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(inspector(scope, receive, send), timeout=_TIMEOUT)


async def _trace_http(inspector: Inspector, *, path: str = "/", method: str = "GET") -> None:
    scope, receive, send = http_session(path=path, method=method)
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
            try:
                await _trace_lifespan(inspector)
            except Exception as exc:  # noqa: BLE001
                click.echo(f"Error (lifespan): {exc}", err=True)
        for raw in paths:
            scope_type, path = _parse_path(raw)
            try:
                if scope_type == "websocket":
                    await _trace_ws(inspector, path=path)
                else:
                    await _trace_http(inspector, path=path)
            except Exception as exc:  # noqa: BLE001
                click.echo(f"Error ({raw}): {exc}", err=True)

    asyncio.run(_run())
    return inspector.traces
