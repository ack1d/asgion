from typing import Any

from asgion.core._types import Severity
from asgion.spec._checks import (
    ExactlyOneNonNull,
    FieldRequired,
    FieldType,
    FieldValue,
    HeadersFormat,
)
from asgion.spec._protocol import EventSpec, ProtocolSpec

_VALID_WS_SCHEMES = {"ws", "wss"}


def _check_ws_scheme(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    return None if v in _VALID_WS_SCHEMES else f"Unknown scheme: '{v}'"


def _check_subprotocols(v: Any) -> str | None:
    try:
        for item in v:
            if not isinstance(item, str):
                return f"subprotocols items must be str, got {type(item).__name__}"
    except TypeError:
        return f"subprotocols must be iterable, got {type(v).__name__}"
    return None


def _check_client(v: Any) -> str | None:
    if v is None:
        return None
    if not isinstance(v, list | tuple) or len(v) != 2:
        return "client must be None or [host: str, port: int]"
    host, port = v
    if not isinstance(host, str):
        return f"client host must be str, got {type(host).__name__}"
    if not isinstance(port, int):
        return f"client port must be int, got {type(port).__name__}"
    return None


def _check_server(v: Any) -> str | None:
    if v is None:
        return None
    if not isinstance(v, list | tuple) or len(v) != 2:
        return "server must be None or [host: str, port: int]"
    host, port = v
    if not isinstance(host, str):
        return f"server host must be str, got {type(host).__name__}"
    if port is not None and not isinstance(port, int):
        return f"server port must be int or None, got {type(port).__name__}"
    return None


def _check_extensions(v: Any) -> str | None:
    if v is None:
        return None
    if not isinstance(v, dict):
        return f"extensions must be None or dict, got {type(v).__name__}"
    return None


def _check_state(v: Any) -> str | None:
    if not isinstance(v, dict):
        return f"state must be dict, got {type(v).__name__}"
    return None


WS_SPEC = ProtocolSpec(
    name="websocket",
    layer="ws.events",
    scope_layer="ws.scope",
    scope_checks=(
        FieldValue(
            "type",
            lambda v: None if v == "websocket" else f"Expected 'websocket', got '{v}'",
            "WS-001",
            severity=Severity.ERROR,
            summary="Scope type is not 'websocket'",
        ),
        FieldRequired("http_version", "WS-002"),
        FieldType("http_version", str, "WS-003"),
        FieldRequired("scheme", "WS-004"),
        FieldType("scheme", str, "WS-005"),
        FieldValue(
            "scheme",
            _check_ws_scheme,
            "WS-006",
            severity=Severity.WARNING,
            summary="Unknown WebSocket scheme",
            hint="Expected 'ws' or 'wss'",
        ),
        FieldRequired("path", "WS-007"),
        FieldType("path", str, "WS-008"),
        FieldRequired("raw_path", "WS-009"),
        FieldType("raw_path", bytes, "WS-010"),
        FieldRequired("query_string", "WS-011"),
        FieldType("query_string", bytes, "WS-012"),
        FieldRequired("root_path", "WS-013"),
        FieldType("root_path", str, "WS-014"),
        FieldRequired("headers", "WS-015"),
        HeadersFormat(
            "headers",
            "WS-016",
            lowercase_rule_id="WS-019",
            name_type_rule_id="WS-017",
            value_type_rule_id="WS-018",
        ),
        FieldRequired("subprotocols", "WS-020"),
        FieldValue(
            "subprotocols",
            _check_subprotocols,
            "WS-021",
            severity=Severity.ERROR,
            summary="Invalid subprotocols format",
            hint="subprotocols must be an iterable of str",
        ),
        FieldValue(
            "client",
            _check_client,
            "WS-022",
            severity=Severity.ERROR,
            summary="Invalid client format in WebSocket scope",
        ),
        FieldValue(
            "server",
            _check_server,
            "WS-023",
            severity=Severity.ERROR,
            summary="Invalid server format in WebSocket scope",
        ),
        FieldValue(
            "extensions",
            _check_extensions,
            "WS-024",
            severity=Severity.ERROR,
            summary="Invalid extensions type in WebSocket scope",
        ),
        FieldValue(
            "state",
            _check_state,
            "WS-025",
            severity=Severity.ERROR,
            summary="Invalid state type in WebSocket scope",
        ),
    ),
    events=(
        EventSpec(
            "websocket.receive",
            "receive",
            checks=(
                FieldType("bytes", bytes, "WE-002", nullable=True),
                FieldType("text", str, "WE-003", nullable=True),
                ExactlyOneNonNull(
                    "bytes",
                    "text",
                    "WE-001",
                    hint="Set one to a value and the other to None",
                ),
            ),
        ),
        EventSpec(
            "websocket.disconnect",
            "receive",
            checks=(
                FieldType("code", int, "WE-004"),
                FieldType("reason", str, "WE-005", nullable=True, severity=Severity.WARNING),
            ),
        ),
        EventSpec("websocket.connect", "receive"),
        EventSpec(
            "websocket.accept",
            "send",
            checks=(
                FieldType("subprotocol", str, "WE-006", nullable=True, severity=Severity.WARNING),
                HeadersFormat("headers", "WE-007"),
            ),
        ),
        EventSpec(
            "websocket.send",
            "send",
            checks=(
                FieldType("bytes", bytes, "WE-009", nullable=True),
                FieldType("text", str, "WE-010", nullable=True),
                ExactlyOneNonNull("bytes", "text", "WE-008"),
            ),
        ),
        EventSpec(
            "websocket.close",
            "send",
            checks=(
                FieldType("code", int, "WE-011"),
                FieldType("reason", str, "WE-012", nullable=True, severity=Severity.WARNING),
            ),
        ),
        EventSpec(
            "websocket.http.response.start",
            "send",
            checks=(
                FieldType("status", int, "WE-013"),
                HeadersFormat(
                    "headers",
                    "WE-014",
                    summary="WS denial response headers format invalid",
                ),
            ),
        ),
        EventSpec(
            "websocket.http.response.body",
            "send",
            checks=(
                FieldType("body", bytes, "WE-015"),
                FieldType("more_body", bool, "WE-016", severity=Severity.WARNING),
            ),
        ),
    ),
)
