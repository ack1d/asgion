import pytest

from asgion.core.context import ConnectionContext
from asgion.spec import ALL_SPECS
from asgion.validators.extension import ExtensionValidator
from asgion.validators.http_fsm import HTTPFSMValidator
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["http"])


@pytest.fixture
def ext_validator() -> ExtensionValidator:
    return ExtensionValidator()


# --- HE-015: trailers headers format ---


def test_he020_trailers_bad_headers(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.trailers", "headers": "bad"})
    assert_violation(ctx, "HE-015")


def test_he020_trailers_valid_headers(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.trailers", "headers": [(b"checksum", b"abc")]}
    )
    matching = [v for v in ctx.violations if v.rule_id == "HE-015"]
    assert matching == []


# --- HE-016/022/023: http.response.push ---


def test_he021_push_missing_path(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.push", "headers": []})
    assert_violation(ctx, "HE-016")


def test_he022_push_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.push", "path": b"/resource", "headers": []}
    )
    assert_violation(ctx, "HE-017")


def test_he023_push_headers_bad(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.push", "path": "/resource", "headers": "bad"}
    )
    assert_violation(ctx, "HE-018")


def test_push_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.push", "path": "/resource", "headers": []})
    assert_no_violations(ctx)


# --- HE-019: http.response.zerocopysend ---


def test_he024_zerocopysend_missing_file(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.zerocopysend"})
    assert_violation(ctx, "HE-019")


def test_zerocopysend_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.zerocopysend", "file": 3})
    assert_no_violations(ctx)


# --- HE-020/026: http.response.pathsend ---


def test_he025_pathsend_missing_path(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.pathsend"})
    assert_violation(ctx, "HE-020")


def test_he026_pathsend_path_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.pathsend", "path": 123})
    assert_violation(ctx, "HE-021")


def test_pathsend_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.pathsend", "path": "/file.txt"})
    assert_no_violations(ctx)


# --- HE-022: http.response.early_hint ---


def test_he027_early_hint_headers_bad(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.early_hint", "headers": 42})
    assert_violation(ctx, "HE-022")


def test_early_hint_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx, {"type": "http.response.early_hint", "headers": [(b"link", b"</style.css>")]}
    )
    assert_no_violations(ctx)


# --- HE-023: http.response.debug ---


def test_he028_debug_info_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.debug", "info": "not dict"})
    assert_violation(ctx, "HE-023")


def test_debug_valid(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.debug", "info": {"key": "val"}})
    assert_no_violations(ctx)


def test_debug_info_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.debug"})
    assert_no_violations(ctx)


# --- EX-009: Gate checks ---


def _make_ext_ctx(*ext_keys: str) -> ConnectionContext:
    extensions = {k: {} for k in ext_keys}
    ctx = make_http_ctx()
    ctx.scope["extensions"] = extensions
    return ctx


def test_ex009_push_without_extension(ext_validator: ExtensionValidator) -> None:
    ctx = make_http_ctx()
    ext_validator.validate_send(ctx, {"type": "http.response.push", "path": "/x", "headers": []})
    assert_violation(ctx, "EX-009")


def test_ex009_push_with_extension_passes(ext_validator: ExtensionValidator) -> None:
    ctx = _make_ext_ctx("http.response.push")
    ext_validator.validate_send(ctx, {"type": "http.response.push", "path": "/x", "headers": []})
    matching = [v for v in ctx.violations if v.rule_id == "EX-009"]
    assert matching == []


def test_ex009_pathsend_without_extension(ext_validator: ExtensionValidator) -> None:
    ctx = make_http_ctx()
    ext_validator.validate_send(ctx, {"type": "http.response.pathsend", "path": "/f"})
    assert_violation(ctx, "EX-009")


def test_ex009_zerocopysend_without_extension(ext_validator: ExtensionValidator) -> None:
    ctx = make_http_ctx()
    ext_validator.validate_send(ctx, {"type": "http.response.zerocopysend", "file": 3})
    assert_violation(ctx, "EX-009")


def test_ex009_early_hint_without_extension(ext_validator: ExtensionValidator) -> None:
    ctx = make_http_ctx()
    ext_validator.validate_send(ctx, {"type": "http.response.early_hint", "headers": []})
    assert_violation(ctx, "EX-009")


def test_ex009_debug_without_extension(ext_validator: ExtensionValidator) -> None:
    ctx = make_http_ctx()
    ext_validator.validate_send(ctx, {"type": "http.response.debug", "info": {}})
    assert_violation(ctx, "EX-009")


def test_ex009_non_extension_event_ignored(ext_validator: ExtensionValidator) -> None:
    ctx = make_http_ctx()
    ext_validator.validate_send(ctx, {"type": "http.response.start", "status": 200, "headers": []})
    assert_no_violations(ctx)


# --- EX-010: early_hint after response.start ---


def test_ex010_early_hint_after_response_start(ext_validator: ExtensionValidator) -> None:
    ctx = _make_ext_ctx("http.response.early_hint")
    fsm = HTTPFSMValidator()
    fsm.validate_receive(ctx, {"type": "http.request", "body": b"", "more_body": False})
    fsm.validate_send(ctx, {"type": "http.response.start", "status": 200, "headers": []})
    ext_validator.validate_send(ctx, {"type": "http.response.early_hint", "headers": []})
    assert_violation(ctx, "EX-010")


def test_ex010_early_hint_before_response_start_passes(
    ext_validator: ExtensionValidator,
) -> None:
    ctx = _make_ext_ctx("http.response.early_hint")
    ext_validator.validate_send(ctx, {"type": "http.response.early_hint", "headers": []})
    matching = [v for v in ctx.violations if v.rule_id == "EX-010"]
    assert matching == []


# --- EX-011: debug after response.start ---


def test_ex011_debug_after_response_start(ext_validator: ExtensionValidator) -> None:
    ctx = _make_ext_ctx("http.response.debug")
    fsm = HTTPFSMValidator()
    fsm.validate_receive(ctx, {"type": "http.request", "body": b"", "more_body": False})
    fsm.validate_send(ctx, {"type": "http.response.start", "status": 200, "headers": []})
    ext_validator.validate_send(ctx, {"type": "http.response.debug", "info": {}})
    assert_violation(ctx, "EX-011")


def test_ex011_debug_before_response_start_passes(
    ext_validator: ExtensionValidator,
) -> None:
    ctx = _make_ext_ctx("http.response.debug")
    ext_validator.validate_send(ctx, {"type": "http.response.debug", "info": {}})
    matching = [v for v in ctx.violations if v.rule_id == "EX-011"]
    assert matching == []
