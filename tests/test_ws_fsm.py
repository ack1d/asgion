import pytest

from asgion.core._types import WSPhase
from asgion.core.context import ConnectionContext
from asgion.validators.ws_fsm import WebSocketFSMValidator
from tests.conftest import assert_no_violations, assert_violation, make_ws_ctx


@pytest.fixture
def validator() -> WebSocketFSMValidator:
    return WebSocketFSMValidator()


def _drive_to_handshake(validator: WebSocketFSMValidator) -> ConnectionContext:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    return ctx


def _drive_to_connected(validator: WebSocketFSMValidator) -> ConnectionContext:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(ctx, {"type": "websocket.accept"})
    return ctx


def _drive_to_closing(validator: WebSocketFSMValidator) -> ConnectionContext:
    ctx = _drive_to_connected(validator)
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    return ctx


def _drive_to_closed_via_disconnect(validator: WebSocketFSMValidator) -> ConnectionContext:
    ctx = _drive_to_connected(validator)
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000})
    return ctx


def test_wf001_connect_in_handshake_state(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.HANDSHAKE
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    assert_violation(ctx, "WF-001")


def test_wf001_connect_in_connected_state(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_connected(validator)
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    assert_violation(ctx, "WF-001")


def test_wf001_connect_in_closed_state(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_closed_via_disconnect(validator)
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    assert_violation(ctx, "WF-001")


def test_wf001_first_connect_passes(validator: WebSocketFSMValidator) -> None:
    ctx = make_ws_ctx()
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CONNECTING
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    assert_no_violations(ctx)
    assert ctx.ws.phase == WSPhase.HANDSHAKE


def test_wf002_accept_in_connecting_state(validator: WebSocketFSMValidator) -> None:
    ctx = make_ws_ctx()
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CONNECTING
    validator.validate_send(ctx, {"type": "websocket.accept"})
    assert_violation(ctx, "WF-002")


def test_wf002_accept_in_handshake_passes(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(ctx, {"type": "websocket.accept"})
    assert_no_violations(ctx)
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CONNECTED


def test_wf003_send_before_accept_connecting(validator: WebSocketFSMValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"data", "text": None})
    assert_violation(ctx, "WF-003")


def test_wf003_send_before_accept_handshake(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"data", "text": None})
    assert_violation(ctx, "WF-003")


def test_wf003_send_after_accept_passes(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_connected(validator)
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"hello", "text": None})
    assert_no_violations(ctx)


def test_wf004_send_after_close(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_closing(validator)
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CLOSING
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": "late"})
    assert_violation(ctx, "WF-004")


def test_wf005_send_after_disconnect(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_closed_via_disconnect(validator)
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CLOSED
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"too late", "text": None})
    # WF-003 fires because closed means not accepted (accepted checks phase in
    # CONNECTED/CLOSING/CLOSED). Actually accepted returns True for CLOSED.
    # Let's check carefully: ctx.ws.accepted checks phase in
    # (CONNECTED, CLOSING, CLOSED). CLOSED is in that set, so accepted=True.
    # Then phase == CLOSING? No, it's CLOSED. Then ws.closed? Yes.
    # So WF-005 fires.
    assert_violation(ctx, "WF-005")


def test_wf005_close_after_disconnect(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_closed_via_disconnect(validator)
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    assert_violation(ctx, "WF-005")


def test_wf006_duplicate_accept(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_connected(validator)
    validator.validate_send(ctx, {"type": "websocket.accept"})
    assert_violation(ctx, "WF-006")


def test_wf006_single_accept_passes(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(ctx, {"type": "websocket.accept"})
    matching = [v for v in ctx.violations if v.rule_id == "WF-006"]
    assert matching == []


def test_wf007_close_before_accept(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    v = assert_violation(ctx, "WF-007")
    assert v.severity == "info"


def test_wf007_close_after_accept_no_info(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_connected(validator)
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    matching = [v for v in ctx.violations if v.rule_id == "WF-007"]
    assert matching == []


def test_wf008_send_in_closing_state(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_closing(validator)
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": "late msg"})
    assert_violation(ctx, "WF-004")


def test_wf009_denial_start_after_accept(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_connected(validator)
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    assert_violation(ctx, "WF-009")


def test_wf009_denial_start_in_connecting(validator: WebSocketFSMValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    assert_violation(ctx, "WF-009")


def test_wf009_denial_start_in_handshake_passes(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    matching = [v for v in ctx.violations if v.rule_id == "WF-009"]
    assert matching == []
    assert ctx.ws is not None
    assert ctx.ws.denial_started is True
    assert ctx.ws.phase == WSPhase.CLOSING


def test_wf010_denial_body_without_start(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"Forbidden"},
    )
    assert_violation(ctx, "WF-010")


def test_wf010_denial_body_without_start_connecting(validator: WebSocketFSMValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"x"},
    )
    assert_violation(ctx, "WF-010")


def test_wf010_denial_body_after_start_passes(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"Forbidden", "more_body": False},
    )
    matching = [v for v in ctx.violations if v.rule_id == "WF-010"]
    assert matching == []


def test_wf010_denial_body_closes_connection(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"Forbidden", "more_body": False},
    )
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CLOSED


def test_wf010_denial_body_more_body_true_stays_closing(
    validator: WebSocketFSMValidator,
) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"part1", "more_body": True},
    )
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CLOSING


def test_wf012_receive_after_disconnect(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_closed_via_disconnect(validator)
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": b"stale", "text": None})
    v = assert_violation(ctx, "WF-012")
    assert v.severity == "warning"


def test_wf012_receive_after_denial_closed(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_handshake(validator)
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"no", "more_body": False},
    )
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CLOSED
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": "late"})
    assert_violation(ctx, "WF-012")


def test_wf012_receive_while_connected_passes(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_connected(validator)
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": b"data", "text": None})
    matching = [v for v in ctx.violations if v.rule_id == "WF-012"]
    assert matching == []


def test_full_lifecycle_no_violations(validator: WebSocketFSMValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    validator.validate_send(ctx, {"type": "websocket.accept"})
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": b"hello", "text": None})
    validator.validate_send(ctx, {"type": "websocket.send", "bytes": None, "text": "world"})
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    assert_no_violations(ctx)


def test_full_lifecycle_with_disconnect_no_violations(
    validator: WebSocketFSMValidator,
) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    validator.validate_send(ctx, {"type": "websocket.accept"})
    validator.validate_receive(ctx, {"type": "websocket.receive", "bytes": None, "text": "msg"})
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000})
    assert_no_violations(ctx)


def test_denial_lifecycle_no_violations(validator: WebSocketFSMValidator) -> None:
    ctx = make_ws_ctx()
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.start", "status": 403, "headers": []},
    )
    validator.validate_send(
        ctx,
        {"type": "websocket.http.response.body", "body": b"Forbidden", "more_body": False},
    )
    assert_no_violations(ctx)
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CLOSED


def test_state_transitions_connecting_to_handshake(
    validator: WebSocketFSMValidator,
) -> None:
    ctx = make_ws_ctx()
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.CONNECTING
    validator.validate_receive(ctx, {"type": "websocket.connect"})
    assert ctx.ws.phase == WSPhase.HANDSHAKE


def test_state_transitions_handshake_to_connected(
    validator: WebSocketFSMValidator,
) -> None:
    ctx = _drive_to_handshake(validator)
    assert ctx.ws is not None
    assert ctx.ws.phase == WSPhase.HANDSHAKE
    validator.validate_send(ctx, {"type": "websocket.accept"})
    assert ctx.ws.phase == WSPhase.CONNECTED


def test_state_transitions_connected_to_closing(validator: WebSocketFSMValidator) -> None:
    ctx = _drive_to_connected(validator)
    assert ctx.ws is not None
    validator.validate_send(ctx, {"type": "websocket.close", "code": 1000})
    assert ctx.ws.phase == WSPhase.CLOSING


def test_state_transitions_to_closed_via_disconnect(
    validator: WebSocketFSMValidator,
) -> None:
    ctx = _drive_to_connected(validator)
    assert ctx.ws is not None
    validator.validate_receive(ctx, {"type": "websocket.disconnect", "code": 1000})
    assert ctx.ws.phase == WSPhase.CLOSED
