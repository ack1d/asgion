from asgion.core._types import Severity
from asgion.spec._checks import (
    ExactlyOneNonNull,
    FieldType,
    HeadersFormat,
)
from asgion.spec._protocol import EventSpec, ProtocolSpec

WS_SPEC = ProtocolSpec(
    name="websocket",
    layer="ws.events",
    events=(
        EventSpec(
            "websocket.receive",
            "receive",
            checks=(
                FieldType("bytes", bytes, "WE-003", nullable=True),
                FieldType("text", str, "WE-004", nullable=True),
                ExactlyOneNonNull(
                    "bytes",
                    "text",
                    "WE-002",
                    hint="Set one to a value and the other to None",
                ),
            ),
        ),
        EventSpec(
            "websocket.disconnect",
            "receive",
            checks=(
                FieldType("code", int, "WE-005"),
                FieldType("reason", str, "WE-007", nullable=True, severity=Severity.WARNING),
            ),
        ),
        EventSpec("websocket.connect", "receive"),
        EventSpec(
            "websocket.accept",
            "send",
            checks=(
                FieldType("subprotocol", str, "WE-010", nullable=True, severity=Severity.WARNING),
                HeadersFormat("headers", "WE-011"),
            ),
        ),
        EventSpec(
            "websocket.send",
            "send",
            checks=(
                FieldType("bytes", bytes, "WE-013", nullable=True),
                FieldType("text", str, "WE-014", nullable=True),
                ExactlyOneNonNull("bytes", "text", "WE-012"),
            ),
        ),
        EventSpec(
            "websocket.close",
            "send",
            checks=(
                FieldType("code", int, "WE-015"),
                FieldType("reason", str, "WE-016", nullable=True, severity=Severity.WARNING),
            ),
        ),
        EventSpec(
            "websocket.http.response.start",
            "send",
            checks=(
                FieldType("status", int, "WE-020"),
                HeadersFormat(
                    "headers",
                    "WE-021",
                    summary="WS denial response headers format invalid",
                ),
            ),
        ),
        EventSpec(
            "websocket.http.response.body",
            "send",
            checks=(
                FieldType("body", bytes, "WE-022"),
                FieldType("more_body", bool, "WE-023", severity=Severity.WARNING),
            ),
        ),
    ),
)
