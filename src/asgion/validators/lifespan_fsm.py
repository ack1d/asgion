from asgion.core._types import LifespanPhase, Message, Scope, ScopeType
from asgion.core.context import ConnectionContext
from asgion.rules.lifespan_fsm import (
    LF_001,
    LF_002,
    LF_003,
    LF_004,
    LF_005,
    LF_006,
    LF_007,
    LF_008,
    LF_009,
    LF_010,
)
from asgion.validators.base import BaseValidator


class LifespanFSMValidator(BaseValidator):
    """Validates Lifespan lifecycle state machine."""

    def validate_receive(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.lifespan is not None
        msg_type = message.get("type", "")

        if msg_type == "lifespan.startup":
            if ctx.lifespan.phase != LifespanPhase.WAITING:
                ctx.violation(LF_001, state=ctx.lifespan.phase)
            ctx.lifespan.phase = LifespanPhase.STARTING

        elif msg_type == "lifespan.shutdown":
            if ctx.lifespan.phase != LifespanPhase.STARTED:
                ctx.violation(LF_005, state=ctx.lifespan.phase)
            ctx.lifespan.phase = LifespanPhase.SHUTTING_DOWN

    def validate_send(self, ctx: ConnectionContext, message: Message) -> None:
        assert ctx.lifespan is not None
        msg_type = message.get("type", "")

        if msg_type == "lifespan.startup.complete":
            self._validate_startup_complete(ctx)
        elif msg_type == "lifespan.startup.failed":
            self._validate_startup_failed(ctx)
        elif msg_type == "lifespan.shutdown.complete":
            self._validate_shutdown_complete(ctx)
        elif msg_type == "lifespan.shutdown.failed":
            self._validate_shutdown_failed(ctx)

    def validate_scope(self, ctx: ConnectionContext, scope: Scope) -> None:
        if ctx.scope_type != ScopeType.LIFESPAN:
            return

        if "state" in scope:
            ctx.violation(LF_010)

    def validate_complete(self, ctx: ConnectionContext) -> None:
        if ctx.scope_type != ScopeType.LIFESPAN:
            return
        assert ctx.lifespan is not None

        if ctx.lifespan.phase == LifespanPhase.STARTING:
            ctx.violation(LF_009)

        if ctx.lifespan.phase == LifespanPhase.SHUTTING_DOWN:
            ctx.violation(LF_008)

    def _validate_startup_complete(self, ctx: ConnectionContext) -> None:
        assert ctx.lifespan is not None

        if ctx.lifespan.startup_completed:
            ctx.violation(LF_003)
            return

        if ctx.lifespan.startup_failed:
            ctx.violation(LF_004, "lifespan.startup.complete sent after startup.failed")
            return

        if ctx.lifespan.phase != LifespanPhase.STARTING:
            ctx.violation(
                LF_002,
                "lifespan.startup.complete sent in wrong state",
                state=ctx.lifespan.phase,
            )
            return

        ctx.lifespan.startup_completed = True
        ctx.lifespan.phase = LifespanPhase.STARTED

    def _validate_startup_failed(self, ctx: ConnectionContext) -> None:
        assert ctx.lifespan is not None

        if ctx.lifespan.startup_completed:
            ctx.violation(LF_004, "lifespan.startup.failed sent after startup.complete")
            return

        if ctx.lifespan.phase != LifespanPhase.STARTING:
            ctx.violation(
                LF_002,
                "lifespan.startup.failed sent in wrong state",
                state=ctx.lifespan.phase,
            )
            return

        ctx.lifespan.startup_failed = True
        ctx.lifespan.phase = LifespanPhase.FAILED

    def _validate_shutdown_complete(self, ctx: ConnectionContext) -> None:
        assert ctx.lifespan is not None

        if ctx.lifespan.shutdown_failed:
            ctx.violation(LF_007, "lifespan.shutdown.complete sent after shutdown.failed")
            return

        if ctx.lifespan.shutdown_completed:
            ctx.violation(LF_006, "Duplicate lifespan.shutdown.complete")
            return

        if ctx.lifespan.phase != LifespanPhase.SHUTTING_DOWN:
            ctx.violation(
                LF_006,
                "lifespan.shutdown.complete sent in wrong state",
                state=ctx.lifespan.phase,
            )
            return

        ctx.lifespan.shutdown_completed = True
        ctx.lifespan.phase = LifespanPhase.DONE

    def _validate_shutdown_failed(self, ctx: ConnectionContext) -> None:
        assert ctx.lifespan is not None

        if ctx.lifespan.shutdown_completed:
            ctx.violation(LF_007, "lifespan.shutdown.failed sent after shutdown.complete")
            return

        if ctx.lifespan.phase != LifespanPhase.SHUTTING_DOWN:
            ctx.violation(
                LF_006,
                "lifespan.shutdown.failed sent in wrong state",
                state=ctx.lifespan.phase,
            )
            return

        ctx.lifespan.shutdown_failed = True
        ctx.lifespan.phase = LifespanPhase.DONE
