from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any

type Scope = dict[str, Any]
type Message = dict[str, Any]
type Receive = Callable[[], Awaitable[Message]]
type Send = Callable[[Message], Awaitable[None]]
type ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class ScopeType(StrEnum):
    """Known ASGI scope types."""

    HTTP = "http"
    WEBSOCKET = "websocket"
    LIFESPAN = "lifespan"


class Severity(StrEnum):
    """Violation severity levels (ordered lowest → highest)."""

    PERF = "perf"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


SEVERITY_LEVEL: dict[Severity, int] = {
    Severity.PERF: 0,
    Severity.INFO: 1,
    Severity.WARNING: 2,
    Severity.ERROR: 3,
}


class HTTPPhase(StrEnum):
    """HTTP connection state machine phases."""

    WAITING = "waiting"
    REQUEST_RECEIVED = "received"
    RESPONSE_STARTED = "started"
    RESPONSE_BODY = "body"
    COMPLETED = "completed"
    DISCONNECTED = "disconnected"


class WSPhase(StrEnum):
    """WebSocket connection state machine phases."""

    CONNECTING = "connecting"
    HANDSHAKE = "handshake"
    CONNECTED = "connected"
    CLOSING = "closing"
    CLOSED = "closed"


class LifespanPhase(StrEnum):
    """Lifespan state machine phases."""

    WAITING = "waiting"
    STARTING = "starting"
    STARTED = "started"
    FAILED = "failed"
    SHUTTING_DOWN = "shutting_down"
    DONE = "done"
