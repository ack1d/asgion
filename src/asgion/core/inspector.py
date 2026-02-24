from __future__ import annotations

import dataclasses
import logging

from asgion.core._types import ASGIApp, Message, Receive, Scope, ScopeType, Send
from asgion.core.config import AsgionConfig
from asgion.core.context import ConnectionContext, ViolationCallback
from asgion.core.violation import ASGIProtocolError, Violation
from asgion.validators.base import ValidatorRegistry, create_default_registry

logger = logging.getLogger("asgion")

_KNOWN_SCOPE_TYPES = frozenset(ScopeType)


class Inspector:
    """Stateful ASGI wrapper that collects violations across connections.

    Unlike :func:`inspect`, which returns a plain ASGI callable with no way
    to access violations, ``Inspector`` accumulates violations from all
    connections processed through it.

    Example::

        inspector = Inspector(app)
        # ... drive the app via httpx, starlette TestClient, etc.
        assert inspector.violations == []

    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: AsgionConfig | None = None,
        strict: bool = False,
        on_violation: ViolationCallback | None = None,
        exclude_paths: list[str] | None = None,
        exclude_rules: set[str] | None = None,
        registry: ValidatorRegistry | None = None,
    ) -> None:
        _config = config or AsgionConfig()

        if exclude_rules:
            _config = dataclasses.replace(
                _config, exclude_rules=_config.exclude_rules | frozenset(exclude_rules)
            )

        if registry is None:
            registry = create_default_registry(config=_config)

        _exclude_paths = set(exclude_paths) if exclude_paths else set()

        self.violations: list[Violation] = []
        # Capture the list reference, not self — avoids a reference cycle:
        # inspector → asgi_app(_wrapper) → _collect → inspector
        _violations = self.violations
        _user_callback = on_violation

        def _collect(v: Violation) -> None:
            _violations.append(v)
            if _user_callback is not None:
                _user_callback(v)

        # Pre-compute validator lists per scope type once at init time.
        # Avoids a per-connection list allocation from registry.get_validators().
        _validators_by_type = {st: registry.get_validators(st) for st in _KNOWN_SCOPE_TYPES}

        async def _wrapper(scope: Scope, receive: Receive, send: Send) -> None:
            scope_type = scope.get("type", "")

            if scope_type not in _KNOWN_SCOPE_TYPES:
                await app(scope, receive, send)
                return

            if _exclude_paths and scope.get("path", "") in _exclude_paths:
                await app(scope, receive, send)
                return

            ctx = ConnectionContext(
                scope,
                _rule_allowed=_config.allows,
                _on_violation=_collect,
            )
            validators = _validators_by_type[scope_type]

            for v in validators:
                try:
                    v.validate_scope(ctx, scope)
                except Exception:
                    logger.exception("Validator %s.validate_scope() raised", type(v).__name__)

            async def validated_receive() -> Message:
                message = await receive()
                for v in validators:
                    try:
                        v.validate_receive(ctx, message)
                    except Exception:
                        logger.exception("Validator %s.validate_receive() raised", type(v).__name__)
                return message

            async def validated_send(message: Message) -> None:
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
                        logger.exception(
                            "Validator %s.validate_complete() raised", type(v).__name__
                        )

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

        self.asgi_app: ASGIApp = _wrapper

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.asgi_app(scope, receive, send)
