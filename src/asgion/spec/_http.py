from typing import Any

from asgion.core._types import Severity
from asgion.spec._checks import (
    FieldRequired,
    FieldType,
    FieldValue,
    ForbiddenHeader,
    HeadersFormat,
)
from asgion.spec._protocol import EventSpec, ProtocolSpec


def _status_range(v: Any) -> str | None:
    if not isinstance(v, int):
        return None
    return None if 100 <= v <= 599 else f"Unusual HTTP status code: {v}"


HTTP_SPEC = ProtocolSpec(
    name="http",
    layer="http.events",
    invalid_receive_rule_id="HE-005",
    invalid_receive_summary="Invalid HTTP receive event type",
    invalid_receive_hint="Expected 'http.request' or 'http.disconnect'",
    invalid_send_rule_id="HE-019",
    invalid_send_summary="Invalid HTTP send event type",
    events=(
        EventSpec(
            "http.request",
            "receive",
            checks=(
                FieldRequired("body", "HE-001"),
                FieldType("body", bytes, "HE-002"),
                FieldType("more_body", bool, "HE-003", severity=Severity.WARNING),
            ),
        ),
        EventSpec("http.disconnect", "receive"),
        EventSpec(
            "http.response.start",
            "send",
            checks=(
                FieldRequired(
                    "status",
                    "HE-010",
                    summary="http.response.start missing required 'status' field",
                ),
                FieldType("status", int, "HE-011"),
                FieldValue(
                    "status",
                    _status_range,
                    "HE-012",
                    severity=Severity.WARNING,
                    summary="Unusual HTTP status code",
                    hint="Expected status in range 100-599",
                ),
                HeadersFormat(
                    "headers",
                    "HE-013",
                    lowercase_rule_id="HE-014",
                    forbidden=(
                        ForbiddenHeader(
                            b"transfer-encoding",
                            "HE-015",
                            hint="ASGI servers manage transfer-encoding automatically",
                        ),
                    ),
                ),
                FieldType("trailers", bool, "HE-016", severity=Severity.WARNING),
            ),
        ),
        EventSpec(
            "http.response.body",
            "send",
            checks=(
                FieldType("body", bytes, "HE-017"),
                FieldType("more_body", bool, "HE-018", severity=Severity.WARNING),
            ),
        ),
        EventSpec("http.response.trailers", "send"),
        EventSpec("http.response.push", "send"),
        EventSpec("http.response.zerocopysend", "send"),
        EventSpec("http.response.pathsend", "send"),
        EventSpec("http.response.early_hint", "send"),
        EventSpec("http.response.debug", "send"),
    ),
)
