from asgion.core._types import Severity
from asgion.core.context import ConnectionContext
from asgion.spec._checks import (
    ExactlyOneNonNull,
    FieldRequired,
    FieldType,
    FieldValue,
    ForbiddenHeader,
    HeadersFormat,
)
from asgion.spec._compiler import compile_spec
from asgion.spec._protocol import CompiledSpec, EventSpec, ProtocolSpec
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


def _make_spec(**kwargs) -> ProtocolSpec:
    defaults = {
        "name": "test",
        "layer": "test.events",
        "events": (),
    }
    defaults.update(kwargs)
    return ProtocolSpec(**defaults)


def _make_ctx() -> ConnectionContext:
    return make_http_ctx()


def test_compile_empty_spec() -> None:
    spec = _make_spec()
    compiled = compile_spec(spec)
    assert isinstance(compiled, CompiledSpec)
    assert compiled.rules == {}
    assert compiled.receive_dispatch == {}
    assert compiled.send_dispatch == {}
    assert compiled.invalid_receive_rule is None
    assert compiled.invalid_send_rule is None


def test_compile_events_sorted_by_direction() -> None:
    spec = _make_spec(
        events=(
            EventSpec("test.recv", "receive"),
            EventSpec("test.send", "send"),
        )
    )
    compiled = compile_spec(spec)
    assert "test.recv" in compiled.receive_dispatch
    assert "test.send" in compiled.send_dispatch
    assert "test.recv" not in compiled.send_dispatch
    assert "test.send" not in compiled.receive_dispatch


def test_compile_valid_types() -> None:
    spec = _make_spec(
        events=(
            EventSpec("a.recv", "receive"),
            EventSpec("b.recv", "receive"),
            EventSpec("a.send", "send"),
        )
    )
    compiled = compile_spec(spec)
    assert compiled.valid_receive_types == frozenset({"a.recv", "b.recv"})
    assert compiled.valid_send_types == frozenset({"a.send"})


def test_compile_invalid_receive_rule() -> None:
    spec = _make_spec(
        invalid_receive_rule_id="T-001",
        invalid_receive_summary="Bad receive",
        events=(EventSpec("test.recv", "receive"),),
    )
    compiled = compile_spec(spec)
    assert compiled.invalid_receive_rule is not None
    assert compiled.invalid_receive_rule.id == "T-001"
    assert "T-001" in compiled.rules


def test_compile_invalid_send_rule() -> None:
    spec = _make_spec(
        invalid_send_rule_id="T-002",
        invalid_send_summary="Bad send",
        events=(EventSpec("test.send", "send"),),
    )
    compiled = compile_spec(spec)
    assert compiled.invalid_send_rule is not None
    assert compiled.invalid_send_rule.id == "T-002"
    assert "T-002" in compiled.rules


def test_compile_invalid_rule_auto_hint() -> None:
    spec = _make_spec(
        invalid_receive_rule_id="T-001",
        invalid_receive_summary="Bad receive",
        events=(
            EventSpec("a.recv", "receive"),
            EventSpec("b.recv", "receive"),
        ),
    )
    compiled = compile_spec(spec)
    rule = compiled.invalid_receive_rule
    assert rule is not None
    assert "a.recv" in rule.hint
    assert "b.recv" in rule.hint


def test_no_invalid_rule_when_no_id() -> None:
    spec = _make_spec(events=(EventSpec("test.recv", "receive"),))
    compiled = compile_spec(spec)
    assert compiled.invalid_receive_rule is None
    assert compiled.invalid_send_rule is None


def test_field_required_triggers() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldRequired("body", "TR-001"),)),)
    )
    compiled = compile_spec(spec)
    assert "TR-001" in compiled.rules

    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send"})
    assert_violation(ctx, "TR-001")


def test_field_required_passes() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldRequired("body", "TR-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "body": b""})
    assert_no_violations(ctx)


def test_field_required_auto_summary() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldRequired("body", "TR-001"),)),)
    )
    compiled = compile_spec(spec)
    rule = compiled.rules["TR-001"]
    assert "body" in rule.summary
    assert "test.send" in rule.summary


def test_field_type_triggers() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldType("status", int, "TT-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "status": "not int"})
    assert_violation(ctx, "TT-001")


def test_field_type_passes() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldType("status", int, "TT-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "status": 200})
    assert_no_violations(ctx)


def test_field_type_absent_passes() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldType("status", int, "TT-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send"})
    assert_no_violations(ctx)


def test_field_type_nullable_none_passes() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send", "send", checks=(FieldType("data", str, "TT-002", nullable=True),)
            ),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "data": None})
    assert_no_violations(ctx)


def test_field_type_nullable_wrong_type_triggers() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send", "send", checks=(FieldType("data", str, "TT-002", nullable=True),)
            ),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "data": 42})
    assert_violation(ctx, "TT-002")


def test_field_type_tuple_expected() -> None:
    spec = _make_spec(
        events=(
            EventSpec("test.send", "send", checks=(FieldType("value", (int, float), "TT-003"),)),
        )
    )
    compiled = compile_spec(spec)

    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "value": 3.14})
    assert_no_violations(ctx)

    ctx2 = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx2, {"type": "test.send", "value": "bad"})
    assert_violation(ctx2, "TT-003")


def test_field_type_warning_summary_uses_should() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send",
                "send",
                checks=(FieldType("flag", bool, "TT-004", severity=Severity.WARNING),),
            ),
        )
    )
    compiled = compile_spec(spec)
    rule = compiled.rules["TT-004"]
    assert "should be" in rule.summary


def test_field_type_error_summary_uses_must() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send",
                "send",
                checks=(FieldType("flag", bool, "TT-005", severity=Severity.ERROR),),
            ),
        )
    )
    compiled = compile_spec(spec)
    rule = compiled.rules["TT-005"]
    assert "must be" in rule.summary


def test_field_value_triggers() -> None:
    def _check(v: int) -> str | None:
        return None if 100 <= v <= 599 else f"Bad status: {v}"

    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldValue("status", _check, "TV-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "status": 999})
    assert_violation(ctx, "TV-001")


def test_field_value_passes() -> None:
    def _check(v: int) -> str | None:
        return None if 100 <= v <= 599 else f"Bad: {v}"

    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldValue("status", _check, "TV-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "status": 200})
    assert_no_violations(ctx)


def test_field_value_absent_passes() -> None:
    def _check(v: int) -> str | None:
        return "fail"

    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(FieldValue("status", _check, "TV-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send"})
    assert_no_violations(ctx)


def test_exactly_one_non_null_both_none() -> None:
    spec = _make_spec(
        events=(
            EventSpec("test.send", "send", checks=(ExactlyOneNonNull("bytes", "text", "TE-001"),)),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "bytes": None, "text": None})
    assert_violation(ctx, "TE-001")


def test_exactly_one_non_null_both_set() -> None:
    spec = _make_spec(
        events=(
            EventSpec("test.send", "send", checks=(ExactlyOneNonNull("bytes", "text", "TE-001"),)),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "bytes": b"hi", "text": "hi"})
    assert_violation(ctx, "TE-001")


def test_exactly_one_non_null_one_set_passes() -> None:
    spec = _make_spec(
        events=(
            EventSpec("test.send", "send", checks=(ExactlyOneNonNull("bytes", "text", "TE-001"),)),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "bytes": b"hi", "text": None})
    assert_no_violations(ctx)


def test_exactly_one_non_null_both_absent() -> None:
    spec = _make_spec(
        events=(
            EventSpec("test.send", "send", checks=(ExactlyOneNonNull("bytes", "text", "TE-001"),)),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send"})
    assert_violation(ctx, "TE-001")


def test_headers_format_triggers() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(HeadersFormat("headers", "TH-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "headers": "not a list"})
    assert_violation(ctx, "TH-001")


def test_headers_format_valid_passes() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(HeadersFormat("headers", "TH-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "headers": [(b"host", b"localhost")]})
    assert_no_violations(ctx)


def test_headers_format_absent_passes() -> None:
    spec = _make_spec(
        events=(EventSpec("test.send", "send", checks=(HeadersFormat("headers", "TH-001"),)),)
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send"})
    assert_no_violations(ctx)


def test_headers_format_lowercase_rule() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send",
                "send",
                checks=(HeadersFormat("headers", "TH-001", lowercase_rule_id="TH-002"),),
            ),
        )
    )
    compiled = compile_spec(spec)
    assert "TH-002" in compiled.rules

    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "headers": [(b"Content-Type", b"text/html")]})
    assert_violation(ctx, "TH-002")


def test_headers_format_forbidden_header() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send",
                "send",
                checks=(
                    HeadersFormat(
                        "headers",
                        "TH-001",
                        forbidden=(ForbiddenHeader(b"transfer-encoding", "TH-003"),),
                    ),
                ),
            ),
        )
    )
    compiled = compile_spec(spec)
    assert "TH-003" in compiled.rules

    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "headers": [(b"Transfer-Encoding", b"chunked")]})
    assert_violation(ctx, "TH-003")


def test_headers_format_no_forbidden_passes() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send",
                "send",
                checks=(
                    HeadersFormat(
                        "headers",
                        "TH-001",
                        forbidden=(ForbiddenHeader(b"transfer-encoding", "TH-003"),),
                    ),
                ),
            ),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send", "headers": [(b"content-type", b"text/html")]})
    matching = [v for v in ctx.violations if v.rule_id == "TH-003"]
    assert matching == []


def test_multiple_checks_all_fire() -> None:
    spec = _make_spec(
        events=(
            EventSpec(
                "test.send",
                "send",
                checks=(
                    FieldRequired("status", "TM-001"),
                    FieldRequired("headers", "TM-002"),
                ),
            ),
        )
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.send_dispatch["test.send"]:
        fn(ctx, {"type": "test.send"})
    assert_violation(ctx, "TM-001")
    assert_violation(ctx, "TM-002")


def test_http_spec_compiles() -> None:
    from asgion.spec._http import HTTP_SPEC

    compiled = compile_spec(HTTP_SPEC)
    assert len(compiled.rules) > 0
    assert "http.request" in compiled.receive_dispatch
    assert "http.response.start" in compiled.send_dispatch
    assert "http.response.body" in compiled.send_dispatch
    assert compiled.invalid_receive_rule is not None
    assert compiled.invalid_receive_rule.id == "HE-005"


def test_websocket_spec_compiles() -> None:
    from asgion.spec._websocket import WS_SPEC

    compiled = compile_spec(WS_SPEC)
    assert len(compiled.rules) > 0
    assert "websocket.connect" in compiled.receive_dispatch
    assert "websocket.accept" in compiled.send_dispatch
    assert "websocket.send" in compiled.send_dispatch
    assert "websocket.close" in compiled.send_dispatch


def test_lifespan_spec_compiles() -> None:
    from asgion.spec._lifespan import LIFESPAN_SPEC

    compiled = compile_spec(LIFESPAN_SPEC)
    assert len(compiled.rules) > 0
    assert "lifespan.startup" in compiled.receive_dispatch
    assert "lifespan.startup.complete" in compiled.send_dispatch
    assert compiled.invalid_receive_rule is not None
    assert compiled.invalid_receive_rule.id == "LE-001"
    assert compiled.invalid_send_rule is not None
    assert compiled.invalid_send_rule.id == "LE-003"


def test_all_specs_total_rules() -> None:
    from asgion.spec import SPEC_RULES

    assert len(SPEC_RULES) == 62


def test_rule_layer_metadata() -> None:
    from asgion.spec import SPEC_RULES

    for rule in SPEC_RULES.values():
        assert rule.layer in ("http.events", "http.scope", "ws.events", "lifespan.events")
        assert len(rule.scope_types) > 0


# --- Scope checks ---


def test_compile_empty_scope_checks() -> None:
    spec = _make_spec()
    compiled = compile_spec(spec)
    assert compiled.scope_fns == ()


def test_compile_scope_checks_field_required() -> None:
    spec = _make_spec(
        scope_checks=(FieldRequired("type", "TS-001"),),
        scope_layer="test.scope",
    )
    compiled = compile_spec(spec)
    assert len(compiled.scope_fns) == 1
    assert "TS-001" in compiled.rules

    ctx = _make_ctx()
    for fn in compiled.scope_fns:
        fn(ctx, {"not_type": "http"})
    assert_violation(ctx, "TS-001")


def test_compile_scope_checks_field_required_passes() -> None:
    spec = _make_spec(
        scope_checks=(FieldRequired("type", "TS-001"),),
        scope_layer="test.scope",
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.scope_fns:
        fn(ctx, {"type": "http"})
    assert_no_violations(ctx)


def test_compile_scope_checks_field_type() -> None:
    spec = _make_spec(
        scope_checks=(FieldType("type", str, "TS-002"),),
        scope_layer="test.scope",
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.scope_fns:
        fn(ctx, {"type": 123})
    assert_violation(ctx, "TS-002")


def test_compile_scope_checks_field_value() -> None:
    def _check_type(v: str) -> str | None:
        return None if v == "http" else f"Expected 'http', got '{v}'"

    spec = _make_spec(
        scope_checks=(FieldValue("type", _check_type, "TS-003"),),
        scope_layer="test.scope",
    )
    compiled = compile_spec(spec)
    ctx = _make_ctx()
    for fn in compiled.scope_fns:
        fn(ctx, {"type": "wrong"})
    assert_violation(ctx, "TS-003")


def test_compile_scope_checks_uses_scope_layer() -> None:
    spec = _make_spec(
        scope_checks=(FieldRequired("type", "TS-001"),),
        scope_layer="test.scope",
    )
    compiled = compile_spec(spec)
    rule = compiled.rules["TS-001"]
    assert rule.layer == "test.scope"


def test_compile_scope_checks_fallback_layer() -> None:
    spec = _make_spec(
        scope_checks=(FieldRequired("type", "TS-001"),),
    )
    compiled = compile_spec(spec)
    rule = compiled.rules["TS-001"]
    assert rule.layer == "test.events"


def test_compile_scope_checks_multiple() -> None:
    spec = _make_spec(
        scope_checks=(
            FieldRequired("type", "TS-001"),
            FieldType("type", str, "TS-002"),
        ),
        scope_layer="test.scope",
    )
    compiled = compile_spec(spec)
    assert len(compiled.scope_fns) == 2

    ctx = _make_ctx()
    for fn in compiled.scope_fns:
        fn(ctx, {})
    assert_violation(ctx, "TS-001")


def test_compile_scope_checks_auto_summary() -> None:
    spec = _make_spec(
        scope_checks=(FieldRequired("type", "TS-001"),),
        scope_layer="test.scope",
    )
    compiled = compile_spec(spec)
    rule = compiled.rules["TS-001"]
    assert "scope" in rule.summary
    assert "type" in rule.summary
