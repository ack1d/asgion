from asgion.core._types import Message
from asgion.core.context import ConnectionContext
from asgion.rules.extension import EX_009, EX_010, EX_011
from asgion.validators.base import BaseValidator

_EXTENSION_EVENTS = frozenset(
    {
        "http.response.push",
        "http.response.zerocopysend",
        "http.response.pathsend",
        "http.response.early_hint",
        "http.response.debug",
    }
)


class ExtensionValidator(BaseValidator):
    """Validates extension event usage: gate checks and timing."""

    def validate_send(self, ctx: ConnectionContext, message: Message) -> None:
        msg_type = message.get("type", "")
        if msg_type not in _EXTENSION_EVENTS:
            return

        # Gate check: extension must be declared in scope
        extensions = ctx.scope.get("extensions")
        if not isinstance(extensions, dict) or msg_type not in extensions:
            ctx.violation(EX_009, f"'{msg_type}' requires scope['extensions']['{msg_type}']")

        # Timing checks
        if ctx.http is not None:
            if msg_type == "http.response.early_hint" and ctx.http.response_start_count > 0:
                ctx.violation(EX_010)
            elif msg_type == "http.response.debug" and ctx.http.response_start_count > 0:
                ctx.violation(EX_011)
