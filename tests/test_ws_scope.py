from typing import Any

import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_ws_ctx


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["websocket"])


def _valid_scope() -> dict[str, Any]:
    return {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": "/ws",
        "raw_path": b"/ws",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "subprotocols": [],
    }


# --- WS-001: type ---


def test_ws001_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "type": "http"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-001")


def test_ws001_correct_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id == "WS-001"]
    assert matching == []


# --- WS-002/003: http_version ---


def test_ws002_missing_http_version(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["http_version"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-002")


def test_ws003_http_version_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "http_version": 1.1}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-003")


# --- WS-004/005/006: scheme ---


def test_ws004_missing_scheme(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["scheme"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-004")


def test_ws005_scheme_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "scheme": 443}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-005")


def test_ws006_unknown_scheme(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "scheme": "http"}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "WS-006")
    assert v.severity == "warning"


def test_ws006_valid_schemes(validator: SpecEventValidator) -> None:
    for scheme in ("ws", "wss"):
        ctx = make_ws_ctx()
        scope = {**_valid_scope(), "scheme": scheme}
        validator.validate_scope(ctx, scope)
        matching = [v for v in ctx.violations if v.rule_id == "WS-006"]
        assert matching == [], f"scheme '{scheme}' should be valid"


# --- WS-007/008: path ---


def test_ws007_missing_path(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["path"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-007")


def test_ws008_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "path": b"/ws"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-008")


# --- WS-009/010: raw_path ---


def test_ws009_missing_raw_path(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["raw_path"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-009")


def test_ws010_raw_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "raw_path": "/ws"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-010")


# --- WS-011/012: query_string ---


def test_ws011_missing_query_string(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["query_string"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-011")


def test_ws012_query_string_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "query_string": "foo=bar"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-012")


# --- WS-013/014: root_path ---


def test_ws013_missing_root_path(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["root_path"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-013")


def test_ws014_root_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "root_path": b"/app"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-014")


# --- WS-015/016: headers ---


def test_ws015_missing_headers(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["headers"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-015")


def test_ws016_headers_not_iterable(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "headers": 42}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-016")


# --- WS-017/018: header name/value type ---


def test_ws017_header_name_not_bytes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "headers": [("host", b"localhost")]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-017")


def test_ws018_header_value_not_bytes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "headers": [(b"host", "localhost")]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-018")


# --- WS-019: header name lowercase ---


def test_ws019_header_not_lowercase(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "headers": [(b"Host", b"localhost")]}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "WS-019")
    assert v.severity == "warning"


# --- WS-020/021: subprotocols ---


def test_ws020_missing_subprotocols(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = _valid_scope()
    del scope["subprotocols"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-020")


def test_ws021_subprotocols_bad_item(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "subprotocols": [123]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-021")


def test_ws021_subprotocols_not_iterable(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "subprotocols": 42}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-021")


def test_ws021_subprotocols_valid(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "subprotocols": ["graphql-ws", "graphql-transport-ws"]}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "WS-021"]
    assert matching == []


# --- WS-022: client ---


def test_ws022_client_bad_format(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "client": "127.0.0.1"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-022")


def test_ws022_client_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "client": None}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "WS-022"]
    assert matching == []


# --- WS-023: server ---


def test_ws023_server_bad_format(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "server": "localhost"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-023")


def test_ws023_server_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "server": None}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "WS-023"]
    assert matching == []


# --- WS-024: extensions ---


def test_ws024_extensions_bad_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "extensions": ["bad"]}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-024")


def test_ws024_extensions_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "extensions": None}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "WS-024"]
    assert matching == []


# --- WS-025: state ---


def test_ws025_state_bad_type(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "state": "bad"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "WS-025")


def test_ws025_state_dict_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    scope = {**_valid_scope(), "state": {}}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "WS-025"]
    assert matching == []


# --- Full valid scope ---


def test_valid_scope_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_scope(ctx, _valid_scope())
    assert_no_violations(ctx)
