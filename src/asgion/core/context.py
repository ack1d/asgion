import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from asgion.core._types import (
    HTTPPhase,
    LifespanPhase,
    ScopeType,
    WSPhase,
)
from asgion.core.rule import Rule
from asgion.core.violation import Violation

type ViolationCallback = Callable[[Violation], Any]


@dataclass
class HTTPProtocolState:
    """Mutable state for a single HTTP connection."""

    phase: HTTPPhase = HTTPPhase.WAITING
    response_start_count: int = 0
    body_complete: bool = False
    body_chunks_sent: int = 0
    total_body_bytes: int = 0
    response_status: int = 0
    response_has_trailers: bool = False
    disconnected: bool = False
    request_body_complete: bool = False


@dataclass
class WebSocketProtocolState:
    """Mutable state for a single WebSocket connection."""

    phase: WSPhase = WSPhase.CONNECTING
    denial_started: bool = False

    @property
    def accepted(self) -> bool:
        """Whether the WebSocket has been accepted."""
        return self.phase in (WSPhase.CONNECTED, WSPhase.CLOSING, WSPhase.CLOSED)

    @property
    def closed(self) -> bool:
        """Whether the WebSocket connection is closed."""
        return self.phase == WSPhase.CLOSED


@dataclass
class LifespanProtocolState:
    """Mutable state for a single Lifespan connection."""

    phase: LifespanPhase = LifespanPhase.WAITING
    startup_completed: bool = False
    startup_failed: bool = False
    shutdown_completed: bool = False
    shutdown_failed: bool = False


@dataclass
class ConnectionContext:
    """Tracks state for a single ASGI connection (scope invocation).

    Each call to ``app(scope, receive, send)`` gets its own context.
    Only the protocol-specific state matching ``scope_type`` is initialised.
    """

    scope: dict[str, Any]

    scope_type: str = ""
    path: str = ""
    method: str = ""

    violations: list[Violation] = field(default_factory=list)

    http: HTTPProtocolState | None = None
    ws: WebSocketProtocolState | None = None
    lifespan: LifespanProtocolState | None = None

    start_time: float = field(default_factory=time.monotonic)

    events: list[dict[str, Any]] = field(default_factory=list)

    _disabled_rules: frozenset[str] = field(default_factory=frozenset)
    _on_violation: ViolationCallback | None = None

    def __post_init__(self) -> None:
        self.scope_type = self.scope.get("type", "unknown")
        self.path = self.scope.get("path", "")
        self.method = self.scope.get("method", "")

        if self.scope_type == ScopeType.HTTP:
            self.http = HTTPProtocolState()
        elif self.scope_type == ScopeType.WEBSOCKET:
            self.ws = WebSocketProtocolState()
        elif self.scope_type == ScopeType.LIFESPAN:
            self.lifespan = LifespanProtocolState()

    def violation(
        self,
        rule: Rule,
        detail: str = "",
        *,
        hint: str = "",
        **extra: Any,
    ) -> None:
        """Record a violation.

        Args:
            rule: The Rule that was violated.
            detail: Dynamic, runtime-specific message.
                    Falls back to ``rule.summary`` when empty.
            hint: Override the rule's default hint.
            **extra: Additional context data for debugging.

        """
        if rule.id in self._disabled_rules:
            return

        v = Violation(
            rule_id=rule.id,
            severity=rule.severity,
            message=detail or rule.summary,
            hint=hint or rule.hint,
            scope_type=self.scope_type,
            path=self.path,
            method=self.method,
            timestamp=time.monotonic() - self.start_time,
            context=extra or None,
        )
        self.violations.append(v)

        if self._on_violation is not None:
            self._on_violation(v)

    @property
    def elapsed(self) -> float:
        """Seconds since scope started."""
        return time.monotonic() - self.start_time
