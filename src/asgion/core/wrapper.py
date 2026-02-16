import logging

from asgion.core._types import ASGIApp, Message, Receive, Scope, ScopeType, Send
from asgion.core.context import ConnectionContext, ViolationCallback
from asgion.core.violation import ASGIProtocolError
from asgion.validators.base import ValidatorRegistry, create_default_registry

logger = logging.getLogger("asgion")

_KNOWN_SCOPE_TYPES = frozenset(ScopeType)


def inspect(
    app: ASGIApp,
    *,
    strict: bool = False,
    on_violation: ViolationCallback | None = None,
    exclude_paths: list[str] | None = None,
    exclude_rules: set[str] | None = None,
    registry: ValidatorRegistry | None = None,
) -> ASGIApp:
    """Wrap an ASGI app with protocol validation.

    Args:
        app: The ASGI application to wrap.
        strict: If True, raise ASGIProtocolError on any violation.
        on_violation: Optional callback for each violation (called in real-time).
        exclude_paths: Paths to skip validation for.
        exclude_rules: Rule IDs to suppress (e.g. ``{"HF-007", "G-001"}``).
        registry: Custom validator registry. Uses defaults if None.

    Returns:
        Wrapped ASGI application with protocol validation.

    Example::

        from asgion import inspect

        app = inspect(app)  # Zero config, full validation.

    """
    if registry is None:
        registry = create_default_registry()

    _exclude_paths = set(exclude_paths) if exclude_paths else set()
    _disabled_rules = frozenset(exclude_rules) if exclude_rules else frozenset()

    async def wrapper(scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type", "")

        if scope_type not in _KNOWN_SCOPE_TYPES:
            await app(scope, receive, send)
            return

        if _exclude_paths and scope.get("path", "") in _exclude_paths:
            await app(scope, receive, send)
            return

        ctx = ConnectionContext(
            scope,
            _disabled_rules=_disabled_rules,
            _on_violation=on_violation,
        )
        validators = registry.get_validators(scope_type)

        for v in validators:
            try:
                v.validate_scope(ctx, scope)
            except Exception:
                logger.exception("Validator %s.validate_scope() raised", type(v).__name__)

        async def validated_receive() -> Message:
            message = await receive()
            ctx.events.append(
                {
                    "phase": "receive",
                    "type": message.get("type", ""),
                    "t": ctx.elapsed,
                }
            )
            for v in validators:
                try:
                    v.validate_receive(ctx, message)
                except Exception:
                    logger.exception("Validator %s.validate_receive() raised", type(v).__name__)
            return message

        async def validated_send(message: Message) -> None:
            ctx.events.append(
                {
                    "phase": "send",
                    "type": message.get("type", ""),
                    "t": ctx.elapsed,
                }
            )
            for v in validators:
                try:
                    v.validate_send(ctx, message)
                except Exception:
                    logger.exception("Validator %s.validate_send() raised", type(v).__name__)
            await send(message)

        try:
            await app(scope, validated_receive, validated_send)
        finally:
            for v in validators:
                try:
                    v.validate_complete(ctx)
                except Exception:
                    logger.exception("Validator %s.validate_complete() raised", type(v).__name__)

            for violation in ctx.violations:
                logger.debug(
                    "[%s] %s %s: %s",
                    violation.rule_id,
                    violation.severity,
                    violation.path,
                    violation.message,
                )

            if strict and ctx.violations:
                raise ASGIProtocolError(ctx.violations)

    return wrapper
