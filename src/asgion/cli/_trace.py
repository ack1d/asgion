"""CLI ``asgion trace`` command — record ASGI lifecycle traces."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import click

from asgion.cli._driver import DEFAULT_TIMEOUT, drive
from asgion.core.inspector import Inspector

if TYPE_CHECKING:
    from pathlib import Path

    from asgion.trace import TraceRecord


def run_trace(
    app: object,
    *,
    paths: tuple[str, ...] = ("/",),
    trace_dir: str | Path | None = None,
    max_body_size: int = 64 * 1024,
    run_lifespan: bool = True,
    default_method: str = "GET",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
    scope_timeout: float = DEFAULT_TIMEOUT,
) -> list[TraceRecord]:
    """Run ASGI app with tracing and return recorded traces."""
    inspector = Inspector(
        app,  # type: ignore[arg-type]
        trace=True,
        trace_dir=trace_dir,
        max_body_size=max_body_size,
    )

    async def _run() -> None:
        runs = await drive(
            inspector,
            paths,
            run_lifespan=run_lifespan,
            default_method=default_method,
            headers=headers,
            body=body,
            scope_timeout=scope_timeout,
        )
        for run in runs:
            if run.error is not None:
                label = run.path or run.scope_type
                click.echo(f"Error ({label}): {run.error}", err=True)

    asyncio.run(_run())
    return inspector.traces
