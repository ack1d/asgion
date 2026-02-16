from collections.abc import Callable
from dataclasses import dataclass

from asgion.core._types import Message
from asgion.core.context import ConnectionContext
from asgion.core.rule import Rule
from asgion.spec._checks import CheckSpec

type CheckFn = Callable[[ConnectionContext, Message], None]


@dataclass(frozen=True, slots=True)
class EventSpec:
    """Specification for a single ASGI event type."""

    event_type: str  # "http.request"
    direction: str  # "receive" | "send"
    checks: tuple[CheckSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class ProtocolSpec:
    """Specification for an entire ASGI protocol (HTTP, WebSocket, Lifespan)."""

    name: str  # "http"
    layer: str  # "http.events"
    events: tuple[EventSpec, ...]
    scope_checks: tuple[CheckSpec, ...] = ()
    scope_layer: str = ""
    invalid_receive_rule_id: str = ""
    invalid_receive_summary: str = ""
    invalid_receive_hint: str = ""
    invalid_send_rule_id: str = ""
    invalid_send_summary: str = ""
    invalid_send_hint: str = ""


@dataclass(frozen=True)
class CompiledSpec:
    """Result of compiling a ProtocolSpec - rules + dispatch tables."""

    rules: dict[str, Rule]
    receive_dispatch: dict[str, tuple[CheckFn, ...]]
    send_dispatch: dict[str, tuple[CheckFn, ...]]
    valid_receive_types: frozenset[str]
    valid_send_types: frozenset[str]
    invalid_receive_rule: Rule | None
    invalid_send_rule: Rule | None
    scope_fns: tuple[CheckFn, ...] = ()
