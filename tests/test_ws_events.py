from typing import Any

import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_ws_ctx


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["websocket"])


# --- WE-002: receive bytes/text exclusivity ---


def test_we002_receive_both_none(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": None})
    assert_violation(ctx, "WE-002")


def test_we002_receive_both_set(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": b"data", "text": "data"})
    assert_violation(ctx, "WE-002")


def test_we002_receive_neither_present(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive"})
    assert_violation(ctx, "WE-002")


def test_we002_receive_only_bytes_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": b"hello", "text": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-002"]
    assert matching == []


def test_we002_receive_only_text_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": "hello"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-002"]
    assert matching == []


# --- WE-003: receive bytes type ---


@pytest.mark.parametrize(
    "bad_bytes",
    [
        pytest.param("not bytes", id="is_str"),
        pytest.param(42, id="is_int"),
        pytest.param([1, 2, 3], id="is_list"),
    ],
)
def test_we003_receive_bytes_invalid(validator: SpecEventValidator, bad_bytes: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": bad_bytes, "text": None})
    assert_violation(ctx, "WE-003")


def test_we003_receive_bytes_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": "ok"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-003"]
    assert matching == []


def test_we003_receive_bytes_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": b"data", "text": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-003"]
    assert matching == []


# --- WE-004: receive text type ---


@pytest.mark.parametrize(
    "bad_text",
    [
        pytest.param(b"bad", id="is_bytes"),
        pytest.param(123, id="is_int"),
        pytest.param(["a", "b"], id="is_list"),
    ],
)
def test_we004_receive_text_invalid(validator: SpecEventValidator, bad_text: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": bad_text})
    assert_violation(ctx, "WE-004")


def test_we004_receive_text_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": b"ok", "text": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-004"]
    assert matching == []


def test_we004_receive_text_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": "hello"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-004"]
    assert matching == []


# --- WE-005: disconnect code type ---


@pytest.mark.parametrize(
    "bad_code",
    [
        pytest.param("1000", id="is_str"),
        pytest.param(1000.0, id="is_float"),
        pytest.param(None, id="is_none"),
    ],
)
def test_we005_disconnect_code_invalid(validator: SpecEventValidator, bad_code: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": bad_code})
    assert_violation(ctx, "WE-005")


def test_we005_disconnect_code_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000})
    matching = [v for v in ctx.violations if v.rule_id == "WE-005"]
    assert matching == []


# --- WE-007: disconnect reason type ---


@pytest.mark.parametrize(
    "bad_reason",
    [
        pytest.param(42, id="is_int"),
        pytest.param(b"reason", id="is_bytes"),
        pytest.param(["bad"], id="is_list"),
    ],
)
def test_we007_disconnect_reason_invalid(validator: SpecEventValidator, bad_reason: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(
        ctx, {"type": "websocket.disconnect", "code": 1000, "reason": bad_reason}
    )
    assert_violation(ctx, "WE-007")


def test_we007_disconnect_reason_is_int_severity(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000, "reason": 42})
    v = assert_violation(ctx, "WE-007")
    assert v.severity == "warning"


def test_we007_disconnect_reason_is_bytes_severity(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(
        ctx, {"type": "websocket.disconnect", "code": 1000, "reason": b"reason"}
    )
    v = assert_violation(ctx, "WE-007")
    assert v.severity == "warning"


def test_we007_disconnect_reason_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000, "reason": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-007"]
    assert matching == []


def test_we007_disconnect_reason_str_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(
        ctx, {"type": "websocket.disconnect", "code": 1000, "reason": "going away"}
    )
    matching = [v for v in ctx.violations if v.rule_id == "WE-007"]
    assert matching == []


def test_we007_disconnect_reason_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000})
    matching = [v for v in ctx.violations if v.rule_id == "WE-007"]
    assert matching == []


# --- WE-010: accept subprotocol type ---


@pytest.mark.parametrize(
    "bad_subprotocol",
    [
        pytest.param(42, id="is_int"),
        pytest.param(b"graphql", id="is_bytes"),
        pytest.param(["graphql"], id="is_list"),
    ],
)
def test_we010_accept_subprotocol_invalid(
    validator: SpecEventValidator, bad_subprotocol: Any
) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept", "subprotocol": bad_subprotocol})
    assert_violation(ctx, "WE-010")


def test_we010_accept_subprotocol_is_int_severity(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept", "subprotocol": 42})
    v = assert_violation(ctx, "WE-010")
    assert v.severity == "warning"


def test_we010_accept_subprotocol_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept", "subprotocol": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-010"]
    assert matching == []


def test_we010_accept_subprotocol_str_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept", "subprotocol": "graphql-ws"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-010"]
    assert matching == []


def test_we010_accept_subprotocol_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-010"]
    assert matching == []


# --- WE-011: accept headers validation ---


@pytest.mark.parametrize(
    "bad_headers",
    [
        pytest.param(42, id="not_iterable"),
        pytest.param([(b"name",)], id="bad_pair_length"),
        pytest.param([("name", b"value")], id="str_name"),
        pytest.param([(b"name", "value")], id="str_value"),
    ],
)
def test_we011_accept_headers_invalid(validator: SpecEventValidator, bad_headers: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept", "headers": bad_headers})
    assert_violation(ctx, "WE-011")


def test_we011_accept_headers_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "websocket.accept",
            "headers": [(b"sec-websocket-protocol", b"graphql-ws")],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "WE-011"]
    assert matching == []


def test_we011_accept_headers_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-011"]
    assert matching == []


def test_we011_accept_headers_empty_list_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.accept", "headers": []})
    matching = [v for v in ctx.violations if v.rule_id == "WE-011"]
    assert matching == []


# --- WE-012: send bytes/text exclusivity ---


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param(
            {"type": "websocket.send", "bytes": None, "text": None},
            id="both_none",
        ),
        pytest.param(
            {"type": "websocket.send", "bytes": b"data", "text": "data"},
            id="both_set",
        ),
        pytest.param(
            {"type": "websocket.send"},
            id="neither_present",
        ),
    ],
)
def test_we012_send_exclusivity_violation(
    validator: SpecEventValidator, msg: dict[str, Any]
) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, msg)
    assert_violation(ctx, "WE-012")


def test_we012_send_only_bytes_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"hello", "text": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-012"]
    assert matching == []


def test_we012_send_only_text_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": "hello"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-012"]
    assert matching == []


# --- WE-013: send bytes type ---


@pytest.mark.parametrize(
    "bad_bytes",
    [
        pytest.param("not bytes", id="is_str"),
        pytest.param(99, id="is_int"),
        pytest.param([0x00, 0x01], id="is_list"),
    ],
)
def test_we013_send_bytes_invalid(validator: SpecEventValidator, bad_bytes: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": bad_bytes, "text": None})
    assert_violation(ctx, "WE-013")


def test_we013_send_bytes_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": "ok"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-013"]
    assert matching == []


def test_we013_send_bytes_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"binary", "text": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-013"]
    assert matching == []


# --- WE-014: send text type ---


@pytest.mark.parametrize(
    "bad_text",
    [
        pytest.param(b"bad", id="is_bytes"),
        pytest.param(123, id="is_int"),
        pytest.param({"key": "val"}, id="is_dict"),
    ],
)
def test_we014_send_text_invalid(validator: SpecEventValidator, bad_text: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": bad_text})
    assert_violation(ctx, "WE-014")


def test_we014_send_text_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"ok", "text": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-014"]
    assert matching == []


def test_we014_send_text_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": "hello"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-014"]
    assert matching == []


# --- WE-015: close code type ---


@pytest.mark.parametrize(
    "bad_code",
    [
        pytest.param("1000", id="is_str"),
        pytest.param(1000.0, id="is_float"),
        pytest.param(None, id="is_none"),
        pytest.param(b"1000", id="is_bytes"),
    ],
)
def test_we015_close_code_invalid(validator: SpecEventValidator, bad_code: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.close", "code": bad_code})
    assert_violation(ctx, "WE-015")


def test_we015_close_code_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    matching = [v for v in ctx.violations if v.rule_id == "WE-015"]
    assert matching == []


# --- WE-016: close reason type ---


@pytest.mark.parametrize(
    "bad_reason",
    [
        pytest.param(42, id="is_int"),
        pytest.param(b"bye", id="is_bytes"),
        pytest.param(["bye"], id="is_list"),
    ],
)
def test_we016_close_reason_invalid(validator: SpecEventValidator, bad_reason: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000, "reason": bad_reason})
    assert_violation(ctx, "WE-016")


def test_we016_close_reason_is_int_severity(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000, "reason": 42})
    v = assert_violation(ctx, "WE-016")
    assert v.severity == "warning"


def test_we016_close_reason_none_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000, "reason": None})
    matching = [v for v in ctx.violations if v.rule_id == "WE-016"]
    assert matching == []


def test_we016_close_reason_str_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx, {"type": "websocket.close", "code": 1000, "reason": "normal closure"}
    )
    matching = [v for v in ctx.violations if v.rule_id == "WE-016"]
    assert matching == []


def test_we016_close_reason_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    matching = [v for v in ctx.violations if v.rule_id == "WE-016"]
    assert matching == []


# --- WE-020: denial status type ---


@pytest.mark.parametrize(
    "bad_status",
    [
        pytest.param("403", id="is_str"),
        pytest.param(403.0, id="is_float"),
        pytest.param(None, id="is_none"),
        pytest.param(b"403", id="is_bytes"),
    ],
)
def test_we020_denial_status_invalid(validator: SpecEventValidator, bad_status: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.http.response.start", "status": bad_status})
    assert_violation(ctx, "WE-020")


def test_we020_denial_status_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.http.response.start", "status": 403})
    matching = [v for v in ctx.violations if v.rule_id == "WE-020"]
    assert matching == []


# --- WE-021: denial headers validation ---


@pytest.mark.parametrize(
    "bad_headers",
    [
        pytest.param("bad", id="not_iterable"),
        pytest.param([(b"only-one-element",)], id="bad_pair"),
        pytest.param([("content-type", b"text/plain")], id="str_name"),
        pytest.param([(b"content-type", "text/plain")], id="str_value"),
    ],
)
def test_we021_denial_headers_invalid(validator: SpecEventValidator, bad_headers: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": bad_headers},
    )
    assert_violation(ctx, "WE-021")


def test_we021_denial_headers_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "websocket.http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"text/plain")],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "WE-021"]
    assert matching == []


def test_we021_denial_headers_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.http.response.start", "status": 403})
    matching = [v for v in ctx.violations if v.rule_id == "WE-021"]
    assert matching == []


def test_we021_denial_headers_empty_list_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    matching = [v for v in ctx.violations if v.rule_id == "WE-021"]
    assert matching == []


# --- WE-022: denial body type ---


@pytest.mark.parametrize(
    "bad_body",
    [
        pytest.param("not bytes", id="is_str"),
        pytest.param(42, id="is_int"),
        pytest.param(None, id="is_none"),
        pytest.param([0x00], id="is_list"),
    ],
)
def test_we022_denial_body_invalid(validator: SpecEventValidator, bad_body: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.http.response.body", "body": bad_body})
    assert_violation(ctx, "WE-022")


def test_we022_denial_body_valid_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.http.response.body", "body": b"Forbidden"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-022"]
    assert matching == []


# --- WE-023: denial more_body type ---


@pytest.mark.parametrize(
    "bad_more_body",
    [
        pytest.param(1, id="is_int"),
        pytest.param("true", id="is_str"),
        pytest.param(None, id="is_none"),
    ],
)
def test_we023_denial_more_body_invalid(validator: SpecEventValidator, bad_more_body: Any) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"x", "more_body": bad_more_body},
    )
    assert_violation(ctx, "WE-023")


def test_we023_denial_more_body_is_int_severity(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"x", "more_body": 1},
    )
    v = assert_violation(ctx, "WE-023")
    assert v.severity == "warning"


def test_we023_denial_more_body_valid_true_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"x", "more_body": True},
    )
    matching = [v for v in ctx.violations if v.rule_id == "WE-023"]
    assert matching == []


def test_we023_denial_more_body_valid_false_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"x", "more_body": False},
    )
    matching = [v for v in ctx.violations if v.rule_id == "WE-023"]
    assert matching == []


def test_we023_denial_more_body_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.http.response.body", "body": b"x"})
    matching = [v for v in ctx.violations if v.rule_id == "WE-023"]
    assert matching == []


# --- Valid messages: no violations ---


def test_valid_receive_text_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": "hello"})
    assert_no_violations(ctx)


def test_valid_receive_bytes_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(
        ctx, {"type": "websocket.receive", "bytes": b"\x00\x01", "text": None}
    )
    assert_no_violations(ctx)


def test_valid_connect_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    assert_no_violations(ctx)


def test_valid_disconnect_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000, "reason": "bye"})
    assert_no_violations(ctx)


def test_valid_accept_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "websocket.accept",
            "subprotocol": "graphql-ws",
            "headers": [(b"x-custom", b"val")],
        },
    )
    assert_no_violations(ctx)


def test_valid_send_text_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": "msg"})
    assert_no_violations(ctx)


def test_valid_send_bytes_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"msg", "text": None})
    assert_no_violations(ctx)


def test_valid_close_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000, "reason": "normal"})
    assert_no_violations(ctx)


def test_valid_denial_start_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "websocket.http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"text/plain")],
        },
    )
    assert_no_violations(ctx)


def test_valid_denial_body_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "websocket.http.response.body",
            "body": b"Forbidden",
            "more_body": False,
        },
    )
    assert_no_violations(ctx)
