import contextlib

from asgion.core._types import Message, ScopeType
from asgion.core.context import ConnectionContext
from asgion.rules.semantic import SEM_001, SEM_002, SEM_003, SEM_004, SEM_005
from asgion.validators.base import BaseValidator

_NO_BODY_STATUSES = frozenset({204, 304}) | frozenset(range(100, 200))


class SemanticValidator(BaseValidator):
    """Validates semantic HTTP correctness beyond protocol state machine."""

    def validate_send(self, ctx: ConnectionContext, message: Message) -> None:
        if ctx.http is None:
            return

        msg_type = message.get("type", "")
        if msg_type == "http.response.start":
            self._check_response_headers(ctx, message)

    def validate_complete(self, ctx: ConnectionContext) -> None:
        if ctx.scope_type != ScopeType.HTTP:
            return
        if ctx.http is None:
            return

        self._check_content_length(ctx)
        self._check_disconnect_handling(ctx)

    def _check_response_headers(
        self, ctx: ConnectionContext, message: Message
    ) -> None:
        assert ctx.http is not None
        headers = message.get("headers")
        if not isinstance(headers, list | tuple):
            return

        status = message.get("status", 0)
        scheme = ctx.scope.get("scheme", "")
        content_type_count = 0
        has_content_type = False

        for item in headers:
            if not isinstance(item, list | tuple) or len(item) != 2:
                continue
            name, value = item
            if not isinstance(name, bytes):
                continue
            name_lower = name.lower()

            if name_lower == b"content-type":
                content_type_count += 1
                has_content_type = True

            if name_lower == b"content-length":
                self._parse_content_length(ctx, value)

            if name_lower == b"set-cookie" and scheme == "http":
                self._check_set_cookie_secure(ctx, value)

        if content_type_count > 1:
            ctx.violation(SEM_001)

        if (
            not has_content_type
            and isinstance(status, int)
            and 200 <= status <= 299
            and status not in _NO_BODY_STATUSES
        ):
            ctx.violation(SEM_002)

    def _parse_content_length(self, ctx: ConnectionContext, value: object) -> None:
        assert ctx.http is not None
        if not isinstance(value, bytes):
            return
        with contextlib.suppress(ValueError):
            ctx.http.content_length = int(value)

    def _check_set_cookie_secure(self, ctx: ConnectionContext, value: object) -> None:
        if not isinstance(value, bytes):
            return
        parts = {p.strip().lower() for p in value.split(b";")}
        if b"secure" not in parts:
            ctx.violation(SEM_004)

    def _check_content_length(self, ctx: ConnectionContext) -> None:
        assert ctx.http is not None
        cl = ctx.http.content_length
        if cl is None:
            return
        if ctx.http.disconnected:
            return
        actual = ctx.http.total_body_bytes
        if cl != actual:
            ctx.violation(
                SEM_003,
                f"Content-Length: {cl}, actual body: {actual} bytes",
            )

    def _check_disconnect_handling(self, ctx: ConnectionContext) -> None:
        assert ctx.http is not None
        if ctx.http.disconnected:
            return
        if ctx.http.body_complete:
            return
        if ctx.http.response_start_count == 0:
            return
        ctx.violation(SEM_005)
