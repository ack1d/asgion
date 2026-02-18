from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from asgion.core._types import SEVERITY_LEVEL, Message, Scope, Severity
from asgion.core.wrapper import inspect

if TYPE_CHECKING:
    from asgion.core.config import AsgionConfig
    from asgion.core.violation import Violation

_TIMEOUT = 5.0


@dataclass
class CheckResult:
    scope_type: str
    path: str = ""
    method: str = ""
    violations: list[Violation] = field(default_factory=list)
    error: str | None = None


@dataclass
class CheckReport:
    app_path: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def all_violations(self) -> list[Violation]:
        vv: list[Violation] = []
        for r in self.results:
            vv.extend(r.violations)
        return vv

    def filtered(self, min_severity: Severity) -> list[Violation]:
        level = SEVERITY_LEVEL[min_severity]
        return [v for v in self.all_violations if SEVERITY_LEVEL[v.severity] >= level]


async def _run_lifespan(
    app: object,
    *,
    config: AsgionConfig | None = None,
    exclude_rules: set[str] | None = None,
) -> CheckResult:
    violations: list[Violation] = []
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

    wrapped = inspect(
        app,  # type: ignore[arg-type]
        config=config,
        on_violation=violations.append,
        exclude_rules=exclude_rules,
    )
    result = CheckResult(scope_type="lifespan")
    try:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=_TIMEOUT)
    except TimeoutError:
        pass
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
    result.violations = violations
    return result


async def _run_ws(
    app: object,
    *,
    path: str = "/ws",
    config: AsgionConfig | None = None,
    exclude_rules: set[str] | None = None,
) -> CheckResult:
    violations: list[Violation] = []
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
        if phase == "disconnect":
            phase = "done"
            return {"type": "websocket.disconnect", "code": 1000}
        await asyncio.sleep(999)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Message) -> None:
        nonlocal phase
        msg_type = message.get("type", "")
        if msg_type == "websocket.accept" and phase == "connected":
            phase = "disconnect"
        elif msg_type == "websocket.close":
            phase = "done"

    wrapped = inspect(
        app,  # type: ignore[arg-type]
        config=config,
        on_violation=violations.append,
        exclude_rules=exclude_rules,
    )
    result = CheckResult(scope_type="websocket", path=path)
    try:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=_TIMEOUT)
    except TimeoutError:
        pass
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
    result.violations = violations
    return result


async def _run_http(
    app: object,
    *,
    path: str = "/",
    method: str = "GET",
    config: AsgionConfig | None = None,
    exclude_rules: set[str] | None = None,
) -> CheckResult:
    violations: list[Violation] = []
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

    wrapped = inspect(
        app,  # type: ignore[arg-type]
        config=config,
        on_violation=violations.append,
        exclude_rules=exclude_rules,
    )
    result = CheckResult(scope_type="http", path=path, method=method)
    try:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=_TIMEOUT)
    except TimeoutError:
        pass
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
    result.violations = violations
    return result


_WS_PREFIXES = ("ws:", "wss:")
_HTTP_PREFIXES = ("http:", "https:")


def _parse_path(p: str) -> tuple[str, str]:
    """Return (scope_type, path) for a path string with optional protocol prefix."""
    for prefix in _WS_PREFIXES:
        if p.startswith(prefix):
            return "websocket", p[len(prefix) :]
    for prefix in _HTTP_PREFIXES:
        if p.startswith(prefix):
            return "http", p[len(prefix) :]
    return "http", p


def run_check(
    app: object,
    *,
    app_path: str,
    paths: tuple[str, ...] = ("/",),
    config: AsgionConfig | None = None,
    exclude_rules: set[str] | None = None,
    run_lifespan: bool = True,
) -> CheckReport:
    """Run ASGI protocol checks and return a report.

    Each entry in ``paths`` is a plain path (e.g. ``/api``) defaulting to HTTP,
    or a prefixed path to specify the scope type:
    ``http:/path``, ``https:/path``, ``ws:/path``, ``wss:/path``.
    """
    _excluded = exclude_rules
    report = CheckReport(app_path=app_path)

    async def _run() -> None:
        if run_lifespan:
            report.results.append(await _run_lifespan(app, config=config, exclude_rules=_excluded))
        for raw in paths:
            scope_type, path = _parse_path(raw)
            if scope_type == "websocket":
                report.results.append(
                    await _run_ws(app, path=path, config=config, exclude_rules=_excluded)
                )
            else:
                report.results.append(
                    await _run_http(app, path=path, config=config, exclude_rules=_excluded)
                )

    asyncio.run(_run())
    return report
