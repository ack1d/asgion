from typing import Any

import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


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


def test_hs001_correct_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id == "HS-001"]
    assert matching == []


# --- HS-002/003: http_version required + type ---


def test_hs002_missing_http_version(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["http_version"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-002")


def test_hs003_http_version_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "http_version": 1.1}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-003")


def test_hs002_003_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("HS-002", "HS-003")]
    assert matching == []


# --- HS-004: http_version value ---


def test_hs004_unknown_version(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "http_version": "4.0"}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-004")
    assert v.severity == "warning"


def test_hs004_valid_versions(validator: SpecEventValidator) -> None:
    for ver in ("1.0", "1.1", "2", "3"):
        ctx = make_http_ctx()
        scope = {**_valid_scope(), "http_version": ver}
        validator.validate_scope(ctx, scope)
        matching = [v for v in ctx.violations if v.rule_id == "HS-004"]
        assert matching == [], f"http_version '{ver}' should be valid"


# --- HS-005/006: method required + type ---


def test_hs005_missing_method(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["method"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-005")


def test_hs006_method_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "method": 42}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-006")


def test_hs005_006_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("HS-005", "HS-006")]
    assert matching == []


# --- HS-007: method uppercase ---


def test_hs007_lowercase_method(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "method": "get"}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-007")
    assert v.severity == "warning"


def test_hs007_mixed_case_method(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "method": "Get"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-007")


def test_hs007_uppercase_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "method": "POST"}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "HS-007"]
    assert matching == []


# --- HS-008/009: scheme required + type ---


def test_hs008_missing_scheme(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["scheme"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-008")


def test_hs009_scheme_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "scheme": 443}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-009")


def test_hs008_009_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("HS-008", "HS-009")]
    assert matching == []


# --- HS-010: scheme value ---


def test_hs010_unknown_scheme(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "scheme": "ftp"}
    validator.validate_scope(ctx, scope)
    v = assert_violation(ctx, "HS-010")
    assert v.severity == "warning"


def test_hs010_valid_schemes(validator: SpecEventValidator) -> None:
    for scheme in ("http", "https"):
        ctx = make_http_ctx()
        scope = {**_valid_scope(), "scheme": scheme}
        validator.validate_scope(ctx, scope)
        matching = [v for v in ctx.violations if v.rule_id == "HS-010"]
        assert matching == [], f"scheme '{scheme}' should be valid"


# --- HS-011/012: path required + type ---


def test_hs011_missing_path(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["path"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-011")


def test_hs012_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "path": b"/test"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-012")


def test_hs011_012_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("HS-011", "HS-012")]
    assert matching == []


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
    matching = [v for v in ctx.violations if v.rule_id == "HS-013"]
    assert matching == []


# --- HS-014/015: raw_path required + type ---


def test_hs014_missing_raw_path(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["raw_path"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-014")


def test_hs015_raw_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "raw_path": "/test"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-015")


def test_hs014_015_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("HS-014", "HS-015")]
    assert matching == []


# --- HS-016/017: query_string required + type ---


def test_hs016_missing_query_string(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["query_string"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-016")


def test_hs017_query_string_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "query_string": "foo=bar"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-017")


def test_hs016_017_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("HS-016", "HS-017")]
    assert matching == []


# --- HS-018/019: root_path required + type ---


def test_hs018_missing_root_path(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["root_path"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-018")


def test_hs019_root_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "root_path": b"/app"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-019")


def test_hs018_019_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("HS-018", "HS-019")]
    assert matching == []


# --- HS-020: headers required ---


def test_hs020_missing_headers(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = _valid_scope()
    del scope["headers"]
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-020")


def test_hs020_headers_present_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id == "HS-020"]
    assert matching == []


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
    matching = [v for v in ctx.violations if v.rule_id == "HS-021"]
    assert matching == []


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
    matching = [v for v in ctx.violations if v.rule_id == "HS-024"]
    assert matching == []


# --- HS-025: client format ---


def test_hs025_client_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "client": None}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "HS-025"]
    assert matching == []


def test_hs025_client_valid_tuple_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "client": ["127.0.0.1", 8080]}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "HS-025"]
    assert matching == []


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
    matching = [v for v in ctx.violations if v.rule_id == "HS-026"]
    assert matching == []


def test_hs026_server_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": ["localhost", 443]}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "HS-026"]
    assert matching == []


def test_hs026_server_port_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": ["localhost", None]}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "HS-026"]
    assert matching == []


def test_hs026_server_bad_format(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "server": "localhost:443"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-026")


# --- HS-027: extensions type ---


def test_hs027_extensions_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "extensions": None}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "HS-027"]
    assert matching == []


def test_hs027_extensions_dict_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "extensions": {"tls": {}}}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "HS-027"]
    assert matching == []


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
    matching = [v for v in ctx.violations if v.rule_id == "HS-028"]
    assert matching == []


def test_hs028_state_bad_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    scope = {**_valid_scope(), "state": "bad"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "HS-028")


def test_hs028_state_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id == "HS-028"]
    assert matching == []


# --- Full valid scope ---


def test_valid_scope_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_scope(ctx, _valid_scope())
    assert_no_violations(ctx)
