from typing import Any

import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import (
    assert_no_violation,
    assert_no_violations,
    assert_violation,
    make_http_ctx,
)


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["http"])


def _valid_scope() -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/test",
        "raw_path": b"/test",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }


# --- HS-001: scope type ---


def test_hs001_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "type": "websocket"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-001")


# --- Missing required field (HS-002..020 even) ---


@pytest.mark.parametrize(
    ("field", "rule_id"),
    [
        ("http_version", "HS-002"),
        ("method", "HS-005"),
        ("scheme", "HS-008"),
        ("path", "HS-011"),
        ("raw_path", "HS-014"),
        ("query_string", "HS-016"),
        ("root_path", "HS-018"),
        ("headers", "HS-020"),
    ],
)
def test_missing_required_field(validator: SpecEventValidator, field: str, rule_id: str) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope[field]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, rule_id)


# --- Wrong type (HS-003..019 odd) ---


@pytest.mark.parametrize(
    ("field", "bad_value", "rule_id"),
    [
        ("http_version", 1.1, "HS-003"),
        ("method", 42, "HS-006"),
        ("scheme", 443, "HS-009"),
        ("path", b"/test", "HS-012"),
        ("raw_path", "/test", "HS-015"),
        ("query_string", "foo=bar", "HS-017"),
        ("root_path", b"/app", "HS-019"),
    ],
)
def test_wrong_type_field(
    validator: SpecEventValidator, field: str, bad_value: Any, rule_id: str
) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), field: bad_value}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, rule_id)


# --- HS-004: http_version value ---


def test_hs004_unknown_version(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "http_version": "4.0"}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-004")
    assert v.severity == "warning"


@pytest.mark.parametrize("ver", ["1.0", "1.1", "2", "3"])
def test_hs004_valid_versions(validator: SpecEventValidator, ver: str) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "http_version": ver}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-004")


# --- HS-007: method uppercase ---


@pytest.mark.parametrize("method", ["get", "Get"])
def test_hs007_non_uppercase_method(validator: SpecEventValidator, method: str) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "method": method}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-007")
    assert v.severity == "warning"


def test_hs007_uppercase_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "method": "POST"}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-007")


# --- HS-010: scheme value ---


def test_hs010_unknown_scheme(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "scheme": "ftp"}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-010")
    assert v.severity == "warning"


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_hs010_valid_schemes(validator: SpecEventValidator, scheme: str) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "scheme": scheme}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-010")


# --- HS-013: path starts with / ---


def test_hs013_path_no_slash(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "path": "test"}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-013")
    assert v.severity == "warning"


def test_hs013_path_with_slash_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "path": "/api/test"}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-013")


# --- HS-021: headers format ---


def test_hs021_headers_not_iterable(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "headers": "not a list"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-021")


def test_hs021_headers_bad_pair(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "headers": [(b"host",)]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-021")


def test_hs021_valid_headers_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "headers": [(b"host", b"localhost")]}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-021")


# --- HS-022: header name type ---


def test_hs022_header_name_not_bytes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "headers": [("host", b"localhost")]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-022")


# --- HS-023: header value type ---


def test_hs023_header_value_not_bytes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "headers": [(b"host", "localhost")]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-023")


# --- HS-024: header name lowercase ---


def test_hs024_header_name_not_lowercase(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "headers": [(b"Content-Type", b"text/html")]}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-024")
    assert v.severity == "warning"


def test_hs024_lowercase_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "headers": [(b"content-type", b"text/html")]}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-024")


# --- HS-025: client format ---


def test_hs025_client_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "client": None}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-025")


def test_hs025_client_valid_tuple_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "client": ["127.0.0.1", 8080]}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-025")


def test_hs025_client_bad_format(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "client": "127.0.0.1:8080"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-025")


def test_hs025_client_bad_host_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "client": [127, 8080]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-025")


def test_hs025_client_bad_port_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "client": ["127.0.0.1", "8080"]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-025")


# --- HS-026: server format ---


def test_hs026_server_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": None}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-026")


def test_hs026_server_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": ["localhost", 443]}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-026")


def test_hs026_server_port_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": ["localhost", None]}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-026")


def test_hs026_server_bad_format(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": "localhost:443"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-026")


def test_hs026_server_bad_host_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": [127, 443]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-026")


def test_hs026_server_bad_port_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": ["localhost", "443"]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-026")


# --- HS-027: extensions type ---


def test_hs027_extensions_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "extensions": None}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-027")


def test_hs027_extensions_dict_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "extensions": {"tls": {}}}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-027")


def test_hs027_extensions_bad_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "extensions": ["tls"]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-027")


# --- HS-028: state type ---


def test_hs028_state_dict_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "state": {}}
    validator.validate_scope(ctx, scope)
    assert_no_violation(ctx, "HS-028")


def test_hs028_state_bad_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "state": "bad"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-028")


def test_hs028_state_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    assert_no_violation(ctx, "HS-028")


# --- Full valid scope ---


def test_valid_scope_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    assert_no_violations(ctx)
