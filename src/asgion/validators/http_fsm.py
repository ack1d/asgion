from asgion.core._types import HTTPPhase, Message, ScopeType
from asgion.core.context import ConnectionContext
from asgion.rules.http_fsm import HF_003, HF_004, HF_006, HF_007, HF_008, HF_011, HF_014, HF_015
from asgion.validators.base import BaseValidator


class HTTPFSMValidator(BaseValidator):
    """Validates HTTP lifecycle state machine."""

    def validate_receive(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.http is not None
        msg_type = message.get("type", "")

        if msg_type == "http.request":
            more_body = message.get("more_body", False)

            if ctx.http.phase == HTTPPhase.WAITING:
                ctx.http.phase = HTTPPhase.REQUEST_RECEIVED
            elif ctx.http.phase == HTTPPhase.REQUEST_RECEIVED and more_body:
                pass  # Chunked body, stay in REQUEST_RECEIVED

            if not more_body:
                pass

        elif msg_type == "http.disconnect":
            ctx.http.disconnected = True
            ctx.http.phase = HTTPPhase.DISCONNECTED

    def validate_send(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.http is not None
        msg_type = message.get("type", "")

        if msg_type == "http.response.start":
            self._validate_response_start(ctx, message)
        elif msg_type == "http.response.body":
            self._validate_response_body(ctx, message)
        elif msg_type == "http.response.trailers":
            self._validate_trailers(ctx, message)

    def validate_complete(self, ctx: ConnectionContext) -> None:
        if ctx.scope_type != ScopeType.HTTP:
            return
        assert ctx.http is not None

        if (
            ctx.http.phase not in (HTTPPhase.COMPLETED, HTTPPhase.DISCONNECTED)
            and ctx.http.response_start_count > 0
            and not ctx.http.body_complete
        ):
            ctx.violation(HF_008)

    def _validate_response_start(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.http is not None
        ctx.http.response_start_count += 1
        status = message.get("status", 0)
        ctx.http.response_status = status
        ctx.http.response_has_trailers = message.get("trailers", False)

        if ctx.http.disconnected:
            ctx.violation(
                HF_007,
                "http.response.start sent after client disconnected",
                disconnect_time=ctx.elapsed,
            )
            return

        if ctx.http.response_start_count > 1:
            ctx.violation(
                HF_004,
                f"Duplicate http.response.start (count: {ctx.http.response_start_count})",
                first_status=ctx.http.response_status,
                second_status=status,
            )
            return

        ctx.http.phase = HTTPPhase.RESPONSE_STARTED

    def _validate_response_body(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.http is not None
        more_body = message.get("more_body", False)
        body = message.get("body", b"")
        body_len = len(body) if isinstance(body, bytes | str) else 0

        if ctx.http.disconnected:
            ctx.violation(HF_007, "http.response.body sent after client disconnected")
            return

        if ctx.http.response_start_count == 0:
            ctx.violation(HF_003)
            return

        if ctx.http.body_complete:
            ctx.violation(
                HF_006,
                chunks_after_complete=ctx.http.body_chunks_sent,
            )
            return

        ctx.http.body_chunks_sent += 1
        ctx.http.total_body_bytes += body_len
        ctx.http.phase = HTTPPhase.RESPONSE_BODY

        if not more_body:
            ctx.http.body_complete = True
            ctx.http.phase = HTTPPhase.COMPLETED

            if ctx.method == "HEAD" and ctx.http.total_body_bytes > 0:
                ctx.violation(
                    HF_014,
                    f"HEAD request response has non-empty body ({ctx.http.total_body_bytes} bytes)",
                )

            if ctx.http.response_status in (204, 304) or (
                100 <= ctx.http.response_status < 200 and ctx.http.total_body_bytes > 0
            ):
                ctx.violation(
                    HF_015,
                    f"Status {ctx.http.response_status} response has body ({ctx.http.total_body_bytes} bytes)",
                )

    def _validate_trailers(self, ctx: ConnectionContext, _message: Message) -> None:
        assert ctx.http is not None

        if not ctx.http.response_has_trailers:
            ctx.violation(HF_011)
