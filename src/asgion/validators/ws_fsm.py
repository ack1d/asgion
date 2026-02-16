from asgion.core._types import Message, WSPhase
from asgion.core.context import ConnectionContext
from asgion.rules.ws_fsm import (
    WF_001,
    WF_002,
    WF_003,
    WF_004,
    WF_005,
    WF_006,
    WF_007,
    WF_008,
    WF_009,
    WF_010,
    WF_011,
    WF_012,
)
from asgion.validators.base import BaseValidator


class WebSocketFSMValidator(BaseValidator):
    """Validates WebSocket lifecycle state machine."""

    def validate_receive(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.ws is not None
        msg_type = message.get("type", "")

        if msg_type == "websocket.connect":
            if ctx.ws.phase != WSPhase.CONNECTING:
                ctx.violation(WF_001, state=ctx.ws.phase)
            ctx.ws.phase = WSPhase.HANDSHAKE

        elif msg_type == "websocket.receive":
            if ctx.ws.closed:
                ctx.violation(WF_012)

        elif msg_type == "websocket.disconnect":
            ctx.ws.phase = WSPhase.CLOSED

    def validate_send(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.ws is not None
        msg_type = message.get("type", "")

        if msg_type == "websocket.accept":
            self._validate_accept(ctx)
        elif msg_type == "websocket.send":
            self._validate_send_data(ctx)
        elif msg_type == "websocket.close":
            self._validate_close(ctx)
        elif msg_type == "websocket.http.response.start":
            self._validate_denial_start(ctx)
        elif msg_type == "websocket.http.response.body":
            self._validate_denial_body(ctx, message)

    def _validate_accept(self, ctx: ConnectionContext) -> None:
        assert ctx.ws is not None

        if ctx.ws.accepted:
            ctx.violation(WF_006)
            return

        if ctx.ws.phase != WSPhase.HANDSHAKE:
            ctx.violation(WF_002, state=ctx.ws.phase)
            return

        ctx.ws.phase = WSPhase.CONNECTED

    def _validate_send_data(self, ctx: ConnectionContext) -> None:
        assert ctx.ws is not None

        if ctx.ws.denial_started:
            ctx.violation(WF_011)
            return

        if not ctx.ws.accepted:
            ctx.violation(WF_003)
            return

        if ctx.ws.phase == WSPhase.CLOSING:
            ctx.violation(WF_004)
            return

        if ctx.ws.closed:
            ctx.violation(WF_005)
            return

        if ctx.ws.phase == WSPhase.CLOSED:
            ctx.violation(WF_008)

    def _validate_close(self, ctx: ConnectionContext) -> None:
        assert ctx.ws is not None

        if ctx.ws.closed:
            ctx.violation(WF_005, "websocket.close sent after disconnect")
            return

        if not ctx.ws.accepted and ctx.ws.phase == WSPhase.HANDSHAKE:
            ctx.violation(WF_007)

        ctx.ws.phase = WSPhase.CLOSING

    def _validate_denial_start(self, ctx: ConnectionContext) -> None:
        assert ctx.ws is not None

        if ctx.ws.accepted:
            ctx.violation(
                WF_009,
                "websocket.http.response.start sent after websocket.accept",
            )
            return

        if ctx.ws.phase != WSPhase.HANDSHAKE:
            ctx.violation(WF_009, state=ctx.ws.phase)
            return

        ctx.ws.denial_started = True
        ctx.ws.phase = WSPhase.CLOSING

    def _validate_denial_body(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.ws is not None

        if not ctx.ws.denial_started:
            ctx.violation(WF_010)
            return

        more_body = message.get("more_body", False)
        if not more_body:
            ctx.ws.phase = WSPhase.CLOSED
