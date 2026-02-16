import pytest

from asgion.core._types import HTTPPhase
from asgion.core.context import ConnectionContext
from asgion.validators.http_fsm import HTTPFSMValidator
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


@pytest.fixture
def validator() -> HTTPFSMValidator:
    return HTTPFSMValidator()


def _receive_request(
    validator: HTTPFSMValidator,
    ctx: ConnectionContext,
    *,
    more_body: bool = False,
) -> None:
    validator.validate_receive(
        ctx,
        {
            "type": "http.request",
            "body": b"",
            "more_body": more_body,
        },
    )


def _receive_disconnect(validator: HTTPFSMValidator, ctx: ConnectionContext) -> None:
    validator.validate_receive(ctx, {"type": "http.disconnect"})


def _send_response_start(
    validator: HTTPFSMValidator,
    ctx: ConnectionContext,
    *,
    status: int = 200,
    trailers: bool = False,
) -> None:
    msg: dict = {"type": "http.response.start", "status": status, "headers": []}
    if trailers:
        msg["trailers"] = True
    validator.validate_send(ctx, msg)


def _send_response_body(
    validator: HTTPFSMValidator,
    ctx: ConnectionContext,
    *,
    body: bytes = b"OK",
    more_body: bool = False,
) -> None:
    validator.validate_send(
        ctx,
        {
            "type": "http.response.body",
            "body": body,
            "more_body": more_body,
        },
    )


def _send_trailers(validator: HTTPFSMValidator, ctx: ConnectionContext) -> None:
    validator.validate_send(
        ctx,
        {
            "type": "http.response.trailers",
            "headers": [],
        },
    )


def test_happy_path_simple_response(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx)
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_happy_path_chunked_response(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, body=b"chunk1", more_body=True)
    _send_response_body(validator, ctx, body=b"chunk2", more_body=False)
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_happy_path_with_trailers(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, trailers=True)
    _send_response_body(validator, ctx)
    _send_trailers(validator, ctx)
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_hf003_body_before_start(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_body(validator, ctx)
    assert_violation(ctx, "HF-003")


def test_hf003_body_after_start_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-003"]
    assert matching == []


def test_hf004_duplicate_response_start(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_start(validator, ctx, status=201)
    assert_violation(ctx, "HF-004")


def test_hf004_single_response_start_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-004"]
    assert matching == []


def test_hf006_body_after_complete(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, more_body=False)
    _send_response_body(validator, ctx, body=b"extra")
    assert_violation(ctx, "HF-006")


def test_hf006_chunked_body_no_violation(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, body=b"chunk1", more_body=True)
    _send_response_body(validator, ctx, body=b"chunk2", more_body=False)
    matching = [v for v in ctx.violations if v.rule_id == "HF-006"]
    assert matching == []


def test_hf007_response_start_after_disconnect(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _receive_disconnect(validator, ctx)
    _send_response_start(validator, ctx)
    assert_violation(ctx, "HF-007")


def test_hf007_response_body_after_disconnect(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _receive_disconnect(validator, ctx)
    _send_response_body(validator, ctx)
    assert_violation(ctx, "HF-007")


def test_hf007_no_disconnect_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-007"]
    assert matching == []


def test_hf008_exit_without_body_complete(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    validator.validate_complete(ctx)
    assert_violation(ctx, "HF-008")


def test_hf008_exit_with_complete_body_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, more_body=False)
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-008"]
    assert matching == []


def test_hf008_exit_with_chunked_incomplete(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, body=b"chunk1", more_body=True)
    validator.validate_complete(ctx)
    assert_violation(ctx, "HF-008")


def test_hf008_exit_before_any_response_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-008"]
    assert matching == []


def test_hf008_disconnected_before_body_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _receive_disconnect(validator, ctx)
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-008"]
    assert matching == []


def test_hf010_trailers_flag_but_no_trailers_sent(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, trailers=True)
    _send_response_body(validator, ctx)
    validator.validate_complete(ctx)
    assert_violation(ctx, "HF-010")


def test_hf010_trailers_flag_with_trailers_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, trailers=True)
    _send_response_body(validator, ctx)
    _send_trailers(validator, ctx)
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-010"]
    assert matching == []


def test_hf010_no_trailers_flag_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, trailers=False)
    _send_response_body(validator, ctx)
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-010"]
    assert matching == []


def test_hf011_trailers_without_flag(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, trailers=False)
    _send_response_body(validator, ctx)
    _send_trailers(validator, ctx)
    assert_violation(ctx, "HF-011")


def test_hf011_trailers_with_flag_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, trailers=True)
    _send_response_body(validator, ctx)
    _send_trailers(validator, ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-011"]
    assert matching == []


def test_hf014_head_response_with_body(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx(method="HEAD")
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, body=b"should not be here")
    v = assert_violation(ctx, "HF-014")
    assert v.severity == "warning"


def test_hf014_head_response_empty_body_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx(method="HEAD")
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, body=b"")
    matching = [v for v in ctx.violations if v.rule_id == "HF-014"]
    assert matching == []


def test_hf014_get_response_with_body_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx(method="GET")
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx, body=b"body content")
    matching = [v for v in ctx.violations if v.rule_id == "HF-014"]
    assert matching == []


def test_hf015_status_204_with_body(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, status=204)
    _send_response_body(validator, ctx, body=b"should not be here")
    v = assert_violation(ctx, "HF-015")
    assert v.severity == "warning"


def test_hf015_status_304_with_body(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, status=304)
    _send_response_body(validator, ctx, body=b"should not be here")
    assert_violation(ctx, "HF-015")


def test_hf015_status_1xx_with_body(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, status=100)
    _send_response_body(validator, ctx, body=b"body")
    assert_violation(ctx, "HF-015")


def test_hf015_status_200_with_body_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, status=200)
    _send_response_body(validator, ctx, body=b"OK")
    matching = [v for v in ctx.violations if v.rule_id == "HF-015"]
    assert matching == []


def test_hf015_status_204_empty_body_still_warns(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx, status=204)
    _send_response_body(validator, ctx, body=b"")
    assert_violation(ctx, "HF-015")


def test_hf001_no_response_start(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    validator.validate_complete(ctx)
    assert_violation(ctx, "HF-001")


def test_hf001_response_start_sent_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _send_response_start(validator, ctx)
    _send_response_body(validator, ctx)
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-001"]
    assert matching == []


def test_hf001_disconnected_no_violation(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx)
    _receive_disconnect(validator, ctx)
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "HF-001"]
    assert matching == []


def test_hf009_receive_after_request_body_complete(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx, more_body=False)
    _receive_request(validator, ctx)
    v = assert_violation(ctx, "HF-009")
    assert v.severity == "info"


def test_hf009_chunked_request_then_extra_receive(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx, more_body=True)
    _receive_request(validator, ctx, more_body=False)
    _receive_request(validator, ctx)
    v = assert_violation(ctx, "HF-009")
    assert v.severity == "info"


def test_hf009_chunked_request_in_progress_passes(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    _receive_request(validator, ctx, more_body=True)
    _receive_request(validator, ctx, more_body=True)
    matching = [v for v in ctx.violations if v.rule_id == "HF-009"]
    assert matching == []


def test_phase_transitions_happy_path(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    assert ctx.http.phase == HTTPPhase.WAITING

    _receive_request(validator, ctx)
    assert ctx.http.phase == HTTPPhase.REQUEST_RECEIVED

    _send_response_start(validator, ctx)
    assert ctx.http.phase == HTTPPhase.RESPONSE_STARTED

    _send_response_body(validator, ctx, body=b"chunk1", more_body=True)
    assert ctx.http.phase == HTTPPhase.RESPONSE_BODY

    _send_response_body(validator, ctx, body=b"chunk2", more_body=False)
    assert ctx.http.phase == HTTPPhase.COMPLETED


def test_phase_transitions_disconnect(validator: HTTPFSMValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None

    _receive_request(validator, ctx)
    _receive_disconnect(validator, ctx)
    assert ctx.http.phase == HTTPPhase.DISCONNECTED
    assert ctx.http.disconnected is True
