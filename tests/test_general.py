import math

import pytest

from asgion.core.context import ConnectionContext
from asgion.validators.general import _MAX_DEPTH, GeneralValidator
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


@pytest.fixture
def validator() -> GeneralValidator:
    return GeneralValidator()


def _make_ctx(scope: dict | None = None) -> ConnectionContext:
    if scope is None:
        scope = {"type": "http", "asgi": {"version": "3.0"}}
    return ConnectionContext(scope)


# --- G-001: scope must be a dict ---


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param([1, 2, 3], id="list"),
        pytest.param("not a dict", id="string"),
        pytest.param(None, id="none"),
        pytest.param(42, id="int"),
        pytest.param(("type", "http"), id="tuple"),
    ],
)
def test_g001_scope_not_dict(validator: GeneralValidator, scope: object) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "G-001")


def test_g001_scope_dict_passes(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http", "asgi": {"version": "3.0"}})
    matching = [v for v in ctx.violations if v.rule_id == "G-001"]
    assert matching == []


# --- G-002: scope must contain 'type' ---


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param({"asgi": {"version": "3.0"}}, id="missing-type-key"),
        pytest.param({}, id="empty-dict"),
    ],
)
def test_g002_scope_missing_type(validator: GeneralValidator, scope: dict) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "G-002")


def test_g002_scope_has_type_passes(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http", "asgi": {"version": "3.0"}})
    matching = [v for v in ctx.violations if v.rule_id == "G-002"]
    assert matching == []


# --- G-003: scope['type'] must be a str ---


@pytest.mark.parametrize(
    "type_val",
    [
        pytest.param(123, id="int"),
        pytest.param(b"http", id="bytes"),
        pytest.param(None, id="none"),
        pytest.param(["http"], id="list"),
    ],
)
def test_g003_scope_type_not_str(validator: GeneralValidator, type_val: object) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": type_val, "asgi": {"version": "3.0"}})
    assert_violation(ctx, "G-003")


def test_g003_scope_type_str_passes(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http", "asgi": {"version": "3.0"}})
    matching = [v for v in ctx.violations if v.rule_id == "G-003"]
    assert matching == []


# --- G-004: scope type must be known ---


@pytest.mark.parametrize(
    "type_val",
    [
        pytest.param("ftp", id="unknown-ftp"),
        pytest.param("", id="empty-string"),
    ],
)
def test_g004_scope_type_unknown(validator: GeneralValidator, type_val: str) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": type_val, "asgi": {"version": "3.0"}})
    assert_violation(ctx, "G-004")


@pytest.mark.parametrize(
    "type_val",
    [
        pytest.param("http", id="http"),
        pytest.param("websocket", id="websocket"),
        pytest.param("lifespan", id="lifespan"),
    ],
)
def test_g004_scope_type_valid_passes(validator: GeneralValidator, type_val: str) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": type_val, "asgi": {"version": "3.0"}})
    matching = [v for v in ctx.violations if v.rule_id == "G-004"]
    assert matching == []


# --- G-005: message must be a dict ---


@pytest.mark.parametrize(
    "message",
    [
        pytest.param([1, 2], id="list"),
        pytest.param("not a dict", id="string"),
        pytest.param(None, id="none"),
        pytest.param(42, id="int"),
    ],
)
def test_g005_send_message_not_dict(validator: GeneralValidator, message: object) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, message)
    assert_violation(ctx, "G-005")


def test_g005_receive_message_not_dict(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, "bad")
    assert_violation(ctx, "G-005")


def test_g005_message_dict_passes(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.start", "status": 200})
    matching = [v for v in ctx.violations if v.rule_id == "G-005"]
    assert matching == []


# --- G-006: message must contain 'type' ---


@pytest.mark.parametrize(
    ("method", "message"),
    [
        pytest.param("send", {"status": 200}, id="send-missing-type"),
        pytest.param("send", {}, id="send-empty-dict"),
        pytest.param("receive", {"body": b"hello"}, id="receive-missing-type"),
    ],
)
def test_g006_message_missing_type(validator: GeneralValidator, method: str, message: dict) -> None:
    ctx = make_http_ctx()
    getattr(validator, f"validate_{method}")(ctx, message)
    assert_violation(ctx, "G-006")


def test_g006_message_has_type_passes(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.start"})
    matching = [v for v in ctx.violations if v.rule_id == "G-006"]
    assert matching == []


# --- G-007: message['type'] must be a str ---


@pytest.mark.parametrize(
    ("method", "type_val"),
    [
        pytest.param("send", 123, id="send-int"),
        pytest.param("send", b"http.response.start", id="send-bytes"),
        pytest.param("send", None, id="send-none"),
        pytest.param("receive", 999, id="receive-int"),
    ],
)
def test_g007_message_type_not_str(
    validator: GeneralValidator, method: str, type_val: object
) -> None:
    ctx = make_http_ctx()
    getattr(validator, f"validate_{method}")(ctx, {"type": type_val})
    assert_violation(ctx, "G-007")


def test_g007_message_type_str_passes(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.start"})
    matching = [v for v in ctx.violations if v.rule_id == "G-007"]
    assert matching == []


# --- G-008: NaN values forbidden ---


@pytest.mark.parametrize(
    ("method", "message"),
    [
        pytest.param(
            "send",
            {"type": "http.response.start", "value": float("nan")},
            id="send-top-level",
        ),
        pytest.param(
            "send",
            {"type": "test", "nested": {"deep": float("nan")}},
            id="send-nested-dict",
        ),
        pytest.param(
            "send",
            {"type": "test", "items": [1, 2, float("nan")]},
            id="send-nested-list",
        ),
        pytest.param(
            "receive",
            {"type": "test", "x": float("nan")},
            id="receive",
        ),
    ],
)
def test_g008_nan(validator: GeneralValidator, method: str, message: dict) -> None:
    ctx = make_http_ctx()
    getattr(validator, f"validate_{method}")(ctx, message)
    assert_violation(ctx, "G-008")


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(3.14, id="regular-float"),
        pytest.param(0.0, id="zero"),
    ],
)
def test_g008_valid_float_passes(validator: GeneralValidator, value: float) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "test", "value": value})
    matching = [v for v in ctx.violations if v.rule_id == "G-008"]
    assert matching == []


# --- G-009: Infinity values forbidden ---


@pytest.mark.parametrize(
    ("method", "message"),
    [
        pytest.param(
            "send",
            {"type": "test", "value": float("inf")},
            id="send-positive",
        ),
        pytest.param(
            "send",
            {"type": "test", "value": float("-inf")},
            id="send-negative",
        ),
        pytest.param(
            "send",
            {"type": "test", "data": {"x": math.inf}},
            id="send-nested-dict",
        ),
        pytest.param(
            "send",
            {"type": "test", "items": [1, math.inf]},
            id="send-nested-list",
        ),
        pytest.param(
            "receive",
            {"type": "test", "x": float("inf")},
            id="receive",
        ),
    ],
)
def test_g009_infinity(validator: GeneralValidator, method: str, message: dict) -> None:
    ctx = make_http_ctx()
    getattr(validator, f"validate_{method}")(ctx, message)
    assert_violation(ctx, "G-009")


def test_g009_regular_float_passes(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "test", "value": 99.99})
    matching = [v for v in ctx.violations if v.rule_id == "G-009"]
    assert matching == []


# --- G-010: forbidden types ---


class _CustomObj:
    pass


@pytest.mark.parametrize(
    ("method", "message"),
    [
        pytest.param("send", {"type": "test", "items": {1, 2, 3}}, id="send-set"),
        pytest.param("send", {"type": "test", "items": frozenset([1, 2])}, id="send-frozenset"),
        pytest.param("send", {"type": "test", "obj": _CustomObj()}, id="send-custom-object"),
        pytest.param("send", {"type": "test", "items": [1, {2, 3}]}, id="send-nested-in-list"),
        pytest.param(
            "send",
            {"type": "test", "data": {"inner": frozenset()}},
            id="send-nested-in-dict",
        ),
        pytest.param("receive", {"type": "test", "val": {1, 2}}, id="receive-set"),
    ],
)
def test_g010_forbidden(validator: GeneralValidator, method: str, message: dict) -> None:
    ctx = make_http_ctx()
    getattr(validator, f"validate_{method}")(ctx, message)
    assert_violation(ctx, "G-010")


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(
            {"type": "test", "headers": [(b"host", b"localhost")]},
            id="tuple-in-list",
        ),
        pytest.param(
            {"type": "test", "pair": (1, 2)},
            id="tuple-top-level",
        ),
        pytest.param(
            {
                "type": "test",
                "str_val": "hello",
                "bytes_val": b"world",
                "int_val": 42,
                "float_val": 3.14,
                "bool_val": True,
                "none_val": None,
                "list_val": [1, 2, 3],
                "dict_val": {"nested": "ok"},
                "tuple_val": (1, 2),
            },
            id="all-allowed-types",
        ),
    ],
)
def test_g010_allowed_passes(validator: GeneralValidator, message: dict) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, message)
    matching = [v for v in ctx.violations if v.rule_id == "G-010"]
    assert matching == []


# --- G-011: scope must contain 'asgi' ---


def test_g011_scope_missing_asgi(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http"})
    assert_violation(ctx, "G-011")


def test_g011_scope_has_asgi_passes(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http", "asgi": {"version": "3.0"}})
    matching = [v for v in ctx.violations if v.rule_id == "G-011"]
    assert matching == []


# --- G-012: asgi['version'] must be '2.0' or '3.0' ---


@pytest.mark.parametrize(
    "asgi",
    [
        pytest.param({"version": "1.0"}, id="invalid-version"),
        pytest.param({}, id="missing-version"),
        pytest.param({"version": None}, id="none-version"),
        pytest.param({"version": 3}, id="int-version"),
    ],
)
def test_g012_asgi_version_invalid(validator: GeneralValidator, asgi: dict) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http", "asgi": asgi})
    assert_violation(ctx, "G-012")


@pytest.mark.parametrize(
    "version",
    [
        pytest.param("2.0", id="v2"),
        pytest.param("3.0", id="v3"),
    ],
)
def test_g012_asgi_version_valid_passes(validator: GeneralValidator, version: str) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http", "asgi": {"version": version}})
    matching = [v for v in ctx.violations if v.rule_id == "G-012"]
    assert matching == []


# --- G-013: asgi['spec_version'] should be a str ---


@pytest.mark.parametrize(
    "spec_version",
    [
        pytest.param(2.1, id="float"),
        pytest.param(3, id="int"),
        pytest.param(["2.1"], id="list"),
    ],
)
def test_g013_spec_version_invalid(validator: GeneralValidator, spec_version: object) -> None:
    ctx = _make_ctx()
    validator.validate_scope(
        ctx,
        {"type": "http", "asgi": {"version": "3.0", "spec_version": spec_version}},
    )
    assert_violation(ctx, "G-013")


def test_g013_spec_version_float_is_warning(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(
        ctx,
        {"type": "http", "asgi": {"version": "3.0", "spec_version": 2.1}},
    )
    v = assert_violation(ctx, "G-013")
    assert v.severity == "warning"


@pytest.mark.parametrize(
    "spec_version",
    [
        pytest.param("2.1", id="valid-string"),
        pytest.param(None, id="none"),
    ],
)
def test_g013_spec_version_valid_passes(validator: GeneralValidator, spec_version: object) -> None:
    ctx = _make_ctx()
    validator.validate_scope(
        ctx,
        {"type": "http", "asgi": {"version": "3.0", "spec_version": spec_version}},
    )
    matching = [v for v in ctx.violations if v.rule_id == "G-013"]
    assert matching == []


def test_g013_spec_version_absent_passes(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http", "asgi": {"version": "3.0"}})
    matching = [v for v in ctx.violations if v.rule_id == "G-013"]
    assert matching == []


# --- G-014: nesting depth ---


def _build_deeply_nested(depth: int) -> dict:
    msg: dict = {"type": "test", "value": "leaf"}
    current = msg
    for i in range(depth):
        child: dict = {"value": "leaf"} if i == depth - 1 else {}
        current["nested"] = child
        current = child
    return msg


@pytest.mark.parametrize(
    ("method", "depth"),
    [
        pytest.param("send", _MAX_DEPTH + 3, id="send-exceeds-max"),
        pytest.param("send", _MAX_DEPTH + 1, id="send-at-boundary"),
        pytest.param("receive", _MAX_DEPTH + 3, id="receive-exceeds-max"),
    ],
)
def test_g014_nesting_too_deep(validator: GeneralValidator, method: str, depth: int) -> None:
    ctx = make_http_ctx()
    msg = _build_deeply_nested(depth)
    getattr(validator, f"validate_{method}")(ctx, msg)
    assert_violation(ctx, "G-014")


def test_g014_nesting_exceeds_max_is_warning(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    msg = _build_deeply_nested(_MAX_DEPTH + 3)
    validator.validate_send(ctx, msg)
    v = assert_violation(ctx, "G-014")
    assert v.severity == "warning"


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(
            _build_deeply_nested(_MAX_DEPTH - 2),
            id="within-limit",
        ),
        pytest.param(
            {"type": "test", "a": 1, "b": "two", "c": [1, 2, 3]},
            id="flat-message",
        ),
    ],
)
def test_g014_nesting_ok_passes(validator: GeneralValidator, message: dict) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, message)
    matching = [v for v in ctx.violations if v.rule_id == "G-014"]
    assert matching == []


# --- Valid scopes / messages (no violations at all) ---


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param(
            {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}},
            id="http",
        ),
        pytest.param(
            {"type": "websocket", "asgi": {"version": "3.0", "spec_version": "2.4"}},
            id="websocket",
        ),
        pytest.param(
            {"type": "lifespan", "asgi": {"version": "2.0"}},
            id="lifespan",
        ),
    ],
)
def test_valid_scope_no_violations(validator: GeneralValidator, scope: dict) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, scope)
    assert_no_violations(ctx)


def test_valid_message_no_violations(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        },
    )
    assert_no_violations(ctx)


# --- Cascade tests: earlier failure prevents later rules ---


def test_g001_failure_prevents_g002(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, "bad")
    assert_violation(ctx, "G-001")
    matching_g002 = [v for v in ctx.violations if v.rule_id == "G-002"]
    assert matching_g002 == []


def test_g002_failure_prevents_g003(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"nottype": "http"})
    assert_violation(ctx, "G-002")
    matching_g003 = [v for v in ctx.violations if v.rule_id == "G-003"]
    assert matching_g003 == []


def test_g003_failure_prevents_g004(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": 123, "asgi": {"version": "3.0"}})
    assert_violation(ctx, "G-003")
    matching_g004 = [v for v in ctx.violations if v.rule_id == "G-004"]
    assert matching_g004 == []


def test_g005_failure_prevents_g006(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, "not a dict")
    assert_violation(ctx, "G-005")
    matching_g006 = [v for v in ctx.violations if v.rule_id == "G-006"]
    assert matching_g006 == []


def test_g006_failure_prevents_g007(validator: GeneralValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"status": 200})
    assert_violation(ctx, "G-006")
    matching_g007 = [v for v in ctx.violations if v.rule_id == "G-007"]
    assert matching_g007 == []


def test_g011_missing_asgi_prevents_g012(validator: GeneralValidator) -> None:
    ctx = _make_ctx()
    validator.validate_scope(ctx, {"type": "http"})
    assert_violation(ctx, "G-011")
    matching_g012 = [v for v in ctx.violations if v.rule_id == "G-012"]
    assert matching_g012 == []
