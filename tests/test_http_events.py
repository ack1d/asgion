import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["http"])


# --- HE-001: body required ---


def test_he001_missing_body(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, {"type": "http.request"})
    v = assert_violation(ctx, "HE-001")
    assert v.severity == "error"


def test_he001_body_present(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, {"type": "http.request", "body": b""})
    he001 = [v for v in ctx.violations if v.rule_id == "HE-001"]
    assert he001 == []


# --- HE-002: body must be bytes ---


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("string_body", id="string"),
        pytest.param(42, id="int"),
        pytest.param(None, id="none"),
    ],
)
def test_he002_body_not_bytes(validator: SpecEventValidator, body: object) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, {"type": "http.request", "body": body})
    v = assert_violation(ctx, "HE-002")
    assert v.severity == "error"


def test_he002_body_is_bytes(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, {"type": "http.request", "body": b"hello"})
    he002 = [v for v in ctx.violations if v.rule_id == "HE-002"]
    assert he002 == []


# --- HE-003: more_body must be bool ---


@pytest.mark.parametrize(
    "more_body",
    [
        pytest.param("yes", id="string"),
        pytest.param(1, id="int"),
    ],
)
def test_he003_more_body_not_bool(validator: SpecEventValidator, more_body: object) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, {"type": "http.request", "body": b"", "more_body": more_body})
    v = assert_violation(ctx, "HE-003")
    assert v.severity == "warning"


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param({"type": "http.request", "body": b"", "more_body": False}, id="false"),
        pytest.param({"type": "http.request", "body": b"chunk", "more_body": True}, id="true"),
        pytest.param({"type": "http.request", "body": b""}, id="absent"),
    ],
)
def test_he003_more_body_valid(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, msg)
    he003 = [v for v in ctx.violations if v.rule_id == "HE-003"]
    assert he003 == []


# --- HE-004: invalid receive event type ---


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param({"type": "http.bogus"}, id="bogus"),
        pytest.param({"type": "websocket.connect"}, id="wrong_protocol"),
        pytest.param({"type": ""}, id="empty"),
        pytest.param({}, id="missing"),
    ],
)
def test_he005_invalid_receive_type(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, msg)
    v = assert_violation(ctx, "HE-004")
    assert v.severity == "error"


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param({"type": "http.request", "body": b""}, id="request"),
        pytest.param({"type": "http.disconnect"}, id="disconnect"),
    ],
)
def test_he005_valid_receive_type(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, msg)
    he005 = [v for v in ctx.violations if v.rule_id == "HE-004"]
    assert he005 == []


# --- HE-004: missing status ---


def test_he010_missing_status(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.start", "headers": []})
    v = assert_violation(ctx, "HE-005")
    assert v.severity == "error"


def test_he010_status_present(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.start", "status": 200, "headers": []})
    he010 = [v for v in ctx.violations if v.rule_id == "HE-005"]
    assert he010 == []


# --- HE-006: status must be int ---


@pytest.mark.parametrize(
    "status",
    [
        pytest.param("200", id="string"),
        pytest.param(200.0, id="float"),
        pytest.param(None, id="none"),
    ],
)
def test_he011_status_not_int(validator: SpecEventValidator, status: object) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.start", "status": status, "headers": []},
    )
    v = assert_violation(ctx, "HE-006")
    assert v.severity == "error"


def test_he011_status_is_int(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.start", "status": 404, "headers": []},
    )
    he011 = [v for v in ctx.violations if v.rule_id == "HE-006"]
    assert he011 == []


# --- HE-007: status range ---


@pytest.mark.parametrize(
    ("status", "should_fire"),
    [
        pytest.param(99, True, id="99_below"),
        pytest.param(600, True, id="600_above"),
        pytest.param(-1, True, id="negative"),
        pytest.param(0, True, id="zero"),
        pytest.param(100, False, id="100_valid"),
        pytest.param(200, False, id="200_valid"),
        pytest.param(599, False, id="599_valid"),
    ],
)
def test_he012_status_range(validator: SpecEventValidator, status: int, should_fire: bool) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.start", "status": status, "headers": []},
    )
    he012 = [v for v in ctx.violations if v.rule_id == "HE-007"]
    if should_fire:
        assert he012, f"Expected HE-007 for status={status}"
        assert he012[0].severity == "warning"
    else:
        assert not he012, f"Did not expect HE-007 for status={status}"


def test_he012_status_not_int_skipped(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.start", "status": "200", "headers": []},
    )
    he012 = [v for v in ctx.violations if v.rule_id == "HE-007"]
    assert he012 == []


# --- HE-008: header validation ---


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param(42, id="not_iterable"),
        pytest.param([b"not-a-pair"], id="not_pair"),
        pytest.param([("content-type", b"text/plain")], id="name_not_bytes"),
        pytest.param([(b"content-type", "text/plain")], id="value_not_bytes"),
        pytest.param([(b"a", b"b", b"c")], id="three_element_tuple"),
    ],
)
def test_he013_invalid_headers(validator: SpecEventValidator, headers: object) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.start", "status": 200, "headers": headers},
    )
    v = assert_violation(ctx, "HE-008")
    assert v.severity == "error"


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param([(b"content-type", b"text/plain")], id="valid_tuple"),
        pytest.param([], id="empty_list"),
        pytest.param([[b"content-type", b"text/html"]], id="list_of_lists"),
    ],
)
def test_he013_valid_headers(validator: SpecEventValidator, headers: object) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.start", "status": 200, "headers": headers},
    )
    he013 = [v for v in ctx.violations if v.rule_id == "HE-008"]
    assert he013 == []


# --- HE-009: uppercase headers ---


@pytest.mark.parametrize(
    "header_name",
    [
        pytest.param(b"Content-Type", id="title_case"),
        pytest.param(b"X-Custom-Header", id="mixed_case"),
    ],
)
def test_he014_uppercase_header(validator: SpecEventValidator, header_name: bytes) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(header_name, b"value")],
        },
    )
    v = assert_violation(ctx, "HE-009")
    assert v.severity == "warning"


def test_he014_lowercase_header(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        },
    )
    he014 = [v for v in ctx.violations if v.rule_id == "HE-009"]
    assert he014 == []


# --- HE-005: transfer-encoding ---


def test_he015_transfer_encoding_present(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"transfer-encoding", b"chunked")],
        },
    )
    v = assert_violation(ctx, "HE-010")
    assert v.severity == "warning"


def test_he015_transfer_encoding_mixed_case(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"Transfer-Encoding", b"chunked")],
        },
    )
    assert_violation(ctx, "HE-010")


def test_he015_no_transfer_encoding(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/html")],
        },
    )
    he015 = [v for v in ctx.violations if v.rule_id == "HE-010"]
    assert he015 == []


# --- HE-006: trailers must be bool ---


@pytest.mark.parametrize(
    "trailers",
    [
        pytest.param("yes", id="string"),
        pytest.param(1, id="int"),
    ],
)
def test_he016_trailers_not_bool(validator: SpecEventValidator, trailers: object) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [],
            "trailers": trailers,
        },
    )
    v = assert_violation(ctx, "HE-011")
    assert v.severity == "warning"


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
                "trailers": True,
            },
            id="true",
        ),
        pytest.param(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
                "trailers": False,
            },
            id="false",
        ),
        pytest.param(
            {"type": "http.response.start", "status": 200, "headers": []},
            id="absent",
        ),
    ],
)
def test_he016_trailers_valid(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, msg)
    he016 = [v for v in ctx.violations if v.rule_id == "HE-011"]
    assert he016 == []


# --- HE-007: response body must be bytes ---


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("text", id="string"),
        pytest.param(123, id="int"),
    ],
)
def test_he017_body_not_bytes(validator: SpecEventValidator, body: object) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, {"type": "http.response.body", "body": body})
    v = assert_violation(ctx, "HE-012")
    assert v.severity == "error"


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param({"type": "http.response.body", "body": b"hello"}, id="bytes"),
        pytest.param({"type": "http.response.body"}, id="absent"),
        pytest.param({"type": "http.response.body", "body": b""}, id="empty_bytes"),
    ],
)
def test_he017_body_valid(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, msg)
    he017 = [v for v in ctx.violations if v.rule_id == "HE-012"]
    assert he017 == []


# --- HE-008: response more_body must be bool ---


@pytest.mark.parametrize(
    "more_body",
    [
        pytest.param("yes", id="string"),
        pytest.param(0, id="int"),
    ],
)
def test_he018_more_body_not_bool(validator: SpecEventValidator, more_body: object) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.body", "body": b"", "more_body": more_body},
    )
    v = assert_violation(ctx, "HE-013")
    assert v.severity == "warning"


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param(
            {"type": "http.response.body", "body": b"", "more_body": False},
            id="false",
        ),
        pytest.param(
            {"type": "http.response.body", "body": b""},
            id="absent",
        ),
    ],
)
def test_he018_more_body_valid(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, msg)
    he018 = [v for v in ctx.violations if v.rule_id == "HE-013"]
    assert he018 == []


# --- HE-009: invalid send event type ---


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param({"type": "http.bogus.event"}, id="bogus"),
        pytest.param({"type": "http.request"}, id="receive_type_in_send"),
        pytest.param({"type": ""}, id="empty"),
        pytest.param({}, id="missing"),
    ],
)
def test_he019_invalid_send_type(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, msg)
    v = assert_violation(ctx, "HE-014")
    assert v.severity == "error"


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param(
            {"type": "http.response.start", "status": 200, "headers": []},
            id="response_start",
        ),
        pytest.param(
            {"type": "http.response.body", "body": b""},
            id="response_body",
        ),
        pytest.param({"type": "http.response.trailers"}, id="response_trailers"),
        pytest.param({"type": "http.response.push"}, id="response_push"),
    ],
)
def test_he019_valid_send_type(validator: SpecEventValidator, msg: dict[str, object]) -> None:
    ctx = make_http_ctx()
    validator.validate_send(ctx, msg)
    he019 = [v for v in ctx.violations if v.rule_id == "HE-014"]
    assert he019 == []


# --- Valid full messages ---


def test_valid_http_request_receive(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(
        ctx, {"type": "http.request", "body": b"payload", "more_body": False}
    )
    assert_no_violations(ctx)


def test_valid_http_disconnect_receive(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, {"type": "http.disconnect"})
    assert_no_violations(ctx)


def test_valid_response_start_send(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-request-id", b"abc123"),
            ],
        },
    )
    assert_no_violations(ctx)


def test_valid_response_body_send(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {"type": "http.response.body", "body": b'{"ok": true}', "more_body": False},
    )
    assert_no_violations(ctx)


def test_valid_response_start_with_trailers_flag(
    validator: SpecEventValidator,
) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [],
            "trailers": True,
        },
    )
    assert_no_violations(ctx)


# --- Special tests (kept separate) ---


def test_multiple_violations_single_message(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": "bad",
            "headers": 42,
            "trailers": "nope",
        },
    )
    rule_ids = {v.rule_id for v in ctx.violations}
    assert "HE-006" in rule_ids
    assert "HE-008" in rule_ids
    assert "HE-011" in rule_ids


def test_he001_and_he002_both_fire_when_body_missing(
    validator: SpecEventValidator,
) -> None:
    ctx = make_http_ctx()
    validator.validate_receive(ctx, {"type": "http.request"})
    assert_violation(ctx, "HE-001")
    he002 = [v for v in ctx.violations if v.rule_id == "HE-002"]
    assert he002 == []


def test_disabled_rule(validator: SpecEventValidator) -> None:
    ctx = make_http_ctx(disabled_rules=frozenset({"HE-002"}))
    validator.validate_receive(ctx, {"type": "http.request", "body": "not_bytes"})
    he002 = [v for v in ctx.violations if v.rule_id == "HE-002"]
    assert he002 == []
