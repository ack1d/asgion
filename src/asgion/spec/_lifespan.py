from typing import Any

from asgion.core._types import Severity
from asgion.spec._checks import FieldRequired, FieldType, FieldValue
from asgion.spec._protocol import EventSpec, ProtocolSpec


def _check_state(v: Any) -> str | None:
    if not isinstance(v, dict):
        return f"state must be dict, got {type(v).__name__}"
    return None


LIFESPAN_SPEC = ProtocolSpec(
    name="lifespan",
    layer="lifespan.events",
    scope_layer="lifespan.scope",
    scope_checks=(
        FieldValue(
            "type",
            lambda v: None if v == "lifespan" else f"Expected 'lifespan', got '{v}'",
            "LS-001",
            severity=Severity.ERROR,
            summary="Scope type is not 'lifespan'",
        ),
        FieldRequired("asgi", "LS-002"),
        FieldType("asgi", dict, "LS-003"),
        FieldValue(
            "state",
            _check_state,
            "LS-004",
            severity=Severity.ERROR,
            summary="Invalid state type in lifespan scope",
        ),
    ),
    invalid_receive_rule_id="LE-001",
    invalid_receive_summary="Invalid lifespan receive event type",
    invalid_send_rule_id="LE-003",
    invalid_send_summary="Invalid lifespan send event type",
    events=(
        EventSpec("lifespan.startup", "receive"),
        EventSpec("lifespan.shutdown", "receive"),
        EventSpec("lifespan.startup.complete", "send"),
        EventSpec(
            "lifespan.startup.failed",
            "send",
            checks=(FieldType("message", str, "LE-004"),),
        ),
        EventSpec("lifespan.shutdown.complete", "send"),
        EventSpec(
            "lifespan.shutdown.failed",
            "send",
            checks=(FieldType("message", str, "LE-006"),),
        ),
    ),
)
