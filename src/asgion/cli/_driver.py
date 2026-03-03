"""Unified ASGI driving loop for check and trace commands."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from asgion.cli._sessions import http_session, lifespan_session, ws_session

if TYPE_CHECKING:
    from asgion.core.inspector import Inspector

_TIMEOUT = 5.0

_WS_PREFIXES = ("ws:", "wss:")
_HTTP_PREFIXES = ("http:", "https:")


def parse_path(p: str, default_method: str = "GET") -> tuple[str, str, str]:
    """Return (scope_type, path, method) for a path string.

    Supports protocol prefixes (``ws:``, ``http:``) and method prefixes
    (``POST:/api``).  Method prefix is detected as 3-7 uppercase ASCII
    letters before the first ``:``.
    """
    colon = p.find(":")
    if colon != -1:
        prefix = p[:colon]
        rest = p[colon + 1 :]
        low = prefix.lower()
        if low in ("ws", "wss"):
            return "websocket", rest, ""
        if low in ("http", "https"):
            return "http", rest, default_method
        if 3 <= len(prefix) <= 7 and prefix.isascii() and prefix.isupper():
            return "http", rest, prefix
    return "http", p, default_method


@dataclass
class ScopeRun:
    scope_type: str
    path: str
    method: str
    error: str | None = None
    violation_start: int = 0


async def _run_scope(
    inspector: Inspector,
    scope_type: str,
    path: str,
    method: str,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
) -> ScopeRun:
    if scope_type == "lifespan":
        scope, receive, send = lifespan_session()
        run = ScopeRun(scope_type="lifespan", path="", method="")
    elif scope_type == "websocket":
        scope, receive, send = ws_session(path=path, headers=headers)
        run = ScopeRun(scope_type="websocket", path=path, method="")
    else:
        scope, receive, send = http_session(
            path=path,
            method=method,
            headers=headers,
            body=body,
        )
        run = ScopeRun(scope_type="http", path=path, method=method)

    try:
        await asyncio.wait_for(inspector(scope, receive, send), timeout=_TIMEOUT)
    except TimeoutError:
        pass
    except Exception as exc:  # noqa: BLE001
        run.error = str(exc)
    return run


async def drive(
    inspector: Inspector,
    paths: tuple[str, ...],
    *,
    run_lifespan: bool = True,
    default_method: str = "GET",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
) -> list[ScopeRun]:
    """Drive an Inspector through lifespan + paths, return per-scope metadata."""
    runs: list[ScopeRun] = []

    if run_lifespan:
        start = len(inspector.violations)
        run = await _run_scope(inspector, "lifespan", "", "")
        run.violation_start = start
        runs.append(run)

    for raw in paths:
        scope_type, path, method = parse_path(raw, default_method)
        start = len(inspector.violations)
        run = await _run_scope(
            inspector,
            scope_type,
            path,
            method,
            headers=headers,
            body=body,
        )
        run.violation_start = start
        runs.append(run)

    return runs
