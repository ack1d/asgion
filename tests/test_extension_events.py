import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["http"])


# --- HE-020: trailers headers format ---


def test_he020_trailers_bad_headers(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.trailers", "headers": "bad"})
    assert_violation(ctx, "HE-020")


def test_he020_trailers_valid_headers(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.trailers", "headers": [(b"checksum", b"abc")]}
    )
    matching = [v for v in ctx.violations if v.rule_id == "HE-020"]
    assert matching == []


# --- EX-001/002/003: http.response.push ---


def test_ex001_push_missing_path(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.push", "headers": []})
    assert_violation(ctx, "EX-001")


def test_ex002_push_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.push", "path": b"/resource", "headers": []}
    )
    assert_violation(ctx, "EX-002")


def test_ex003_push_headers_bad(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.push", "path": "/resource", "headers": "bad"}
    )
    assert_violation(ctx, "EX-003")


def test_push_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.push", "path": "/resource", "headers": []}
    )
    assert_no_violations(ctx)


# --- EX-004: http.response.zerocopysend ---


def test_ex004_zerocopysend_missing_file(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.zerocopysend"})
    assert_violation(ctx, "EX-004")


def test_zerocopysend_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.zerocopysend", "file": 3})
    assert_no_violations(ctx)


# --- EX-005/006: http.response.pathsend ---


def test_ex005_pathsend_missing_path(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.pathsend"})
    assert_violation(ctx, "EX-005")


def test_ex006_pathsend_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.pathsend", "path": 123})
    assert_violation(ctx, "EX-006")


def test_pathsend_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.pathsend", "path": "/file.txt"})
    assert_no_violations(ctx)


# --- EX-007: http.response.early_hint ---


def test_ex007_early_hint_headers_bad(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.early_hint", "headers": 42})
    assert_violation(ctx, "EX-007")


def test_early_hint_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.early_hint", "headers": [(b"link", b"</style.css>")]}
    )
    assert_no_violations(ctx)


# --- EX-008: http.response.debug ---


def test_ex008_debug_info_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.debug", "info": "not dict"})
    assert_violation(ctx, "EX-008")


def test_debug_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.debug", "info": {"key": "val"}})
    assert_no_violations(ctx)


def test_debug_info_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.debug"})
    assert_no_violations(ctx)
