from asgion.core._types import Message
from asgion.core.context import ConnectionContext
from asgion.spec._protocol import CompiledSpec
from asgion.validators.base import BaseValidator


class SpecEventValidator(BaseValidator):
    """Event validator backed by a CompiledSpec."""

    def __init__(self, compiled: CompiledSpec) -> None:
        self._receive = compiled.receive_dispatch
        self._send = compiled.send_dispatch
        self._invalid_receive = compiled.invalid_receive_rule
        self._invalid_send = compiled.invalid_send_rule

    def validate_receive(self, ctx: ConnectionContext, message: Message) -> None:
        msg_type = message.get("type", "")
        checks = self._receive.get(msg_type)
        if checks is None:
            if self._invalid_receive is not None:
                ctx.violation(
                    self._invalid_receive,
                    f"{self._invalid_receive.summary}: '{msg_type}'",
                )
            return
        for check in checks:
            check(ctx, message)

    def validate_send(self, ctx: ConnectionContext, message: Message) -> None:
        msg_type = message.get("type", "")
        checks = self._send.get(msg_type)
        if checks is None:
            if self._invalid_send is not None:
                ctx.violation(
                    self._invalid_send,
                    f"{self._invalid_send.summary}: '{msg_type}'",
                )
            return
        for check in checks:
            check(ctx, message)
