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

_VALID_HTTP_VERSIONS = {"1.0", "1.1", "2", "3"}
_VALID_SCHEMES = {"http", "https"}


def _status_range(v: Any) -> str | None:
    if not isinstance(v, int):
        return None
    return None if 100 <= v <= 599 else f"Unusual HTTP status code: {v}"


def _check_http_version(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    return None if v in _VALID_HTTP_VERSIONS else f"Unknown http_version: '{v}'"


def _check_method_uppercase(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    return None if v == v.upper() else f"Method should be uppercase, got '{v}'"


def _check_scheme(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    return None if v in _VALID_SCHEMES else f"Unknown scheme: '{v}'"


def _check_path_slash(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    return None if v.startswith("/") else f"Path should start with '/', got '{v}'"


HTTP_SPEC = ProtocolSpec(
    name="http",
    layer="http.events",
    scope_layer="http.scope",
    scope_checks=(
        FieldValue(
            "type",
            lambda v: None if v == "http" else f"Expected 'http', got '{v}'",
            "HS-001",
            severity=Severity.ERROR,
            summary="Scope type is not 'http'",
        ),
        FieldRequired("http_version", "HS-002"),
        FieldType("http_version", str, "HS-003"),
        FieldValue(
            "http_version",
            _check_http_version,
            "HS-004",
            severity=Severity.WARNING,
            summary="Unknown HTTP version in scope",
            hint="Expected one of: 1.0, 1.1, 2, 3",
        ),
        FieldRequired("method", "HS-005"),
        FieldType("method", str, "HS-006"),
        FieldValue(
            "method",
            _check_method_uppercase,
            "HS-007",
            severity=Severity.WARNING,
            summary="HTTP method should be uppercase",
        ),
        FieldRequired("scheme", "HS-008"),
        FieldType("scheme", str, "HS-009"),
        FieldValue(
            "scheme",
            _check_scheme,
            "HS-010",
            severity=Severity.WARNING,
            summary="Unknown HTTP scheme",
            hint="Expected 'http' or 'https'",
        ),
        FieldRequired("path", "HS-011"),
        FieldType("path", str, "HS-012"),
        FieldValue(
            "path",
            _check_path_slash,
            "HS-013",
            severity=Severity.WARNING,
            summary="HTTP path should start with '/'",
        ),
    ),
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
