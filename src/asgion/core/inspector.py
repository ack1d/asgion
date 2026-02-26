from __future__ import annotations

import dataclasses
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from asgion.core._types import ASGIApp, Message, Receive, Scope, ScopeType, Send
from asgion.core.config import AsgionConfig
from asgion.core.context import ConnectionContext, ViolationCallback
from asgion.core.violation import ASGIProtocolError, Violation
from asgion.validators.base import BaseValidator, ValidatorRegistry, create_default_registry

if TYPE_CHECKING:
    from asgion.trace import TraceRecord, TraceStorage

logger = logging.getLogger("asgion")

_KNOWN_SCOPE_TYPES = frozenset(ScopeType)

_ValidatorMap = dict[str, list[BaseValidator]]


class Inspector:
    """Stateful ASGI wrapper that collects violations across connections.

    Unlike :func:`inspect`, which returns a plain ASGI callable with no way
    to access violations, ``Inspector`` accumulates violations from all
    connections processed through it.

    When ``trace=True``, records ASGI lifecycle events as :class:`TraceRecord`
    objects accessible via the :attr:`traces` property.

    Example::

        inspector = Inspector(app)
        # ... drive the app via httpx, starlette TestClient, etc.
        assert inspector.violations == []

    Tracing example::

        inspector = Inspector(app, trace=True)
        # ... drive the app ...
        for record in inspector.traces:
            print(record.scope.method, record.scope.path)

    """

    _traces: list[TraceRecord]

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
        trace: bool = False,
        sample_rate: float = 1.0,
        trace_dir: str | Path | None = None,
        storage: TraceStorage | None = None,
        max_body_size: int = 64 * 1024,
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
        _validators_by_type: _ValidatorMap = {
            st: registry.get_validators(st) for st in _KNOWN_SCOPE_TYPES
        }

        if trace:
            self.asgi_app: ASGIApp = _build_traced_wrapper(
                app=app,
                config=_config,
                strict=strict,
                collect=_collect,
                exclude_paths=_exclude_paths,
                validators_by_type=_validators_by_type,
                sample_rate=sample_rate,
                trace_dir=trace_dir,
                storage=storage,
                max_body_size=max_body_size,
                traces_out=self,
            )
        else:
            self.asgi_app = _build_fast_wrapper(
                app=app,
                config=_config,
                strict=strict,
                collect=_collect,
                exclude_paths=_exclude_paths,
                validators_by_type=_validators_by_type,
            )

    @property
    def traces(self) -> list[TraceRecord]:
        """Recorded traces. Only available when ``trace=True``."""
        try:
            return self._traces
        except AttributeError:
            msg = "Traces not available: Inspector was created with trace=False"
            raise AttributeError(msg) from None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.asgi_app(scope, receive, send)


def _build_fast_wrapper(
    *,
    app: ASGIApp,
    config: AsgionConfig,
    strict: bool,
    collect: ViolationCallback,
    exclude_paths: set[str],
    validators_by_type: _ValidatorMap,
) -> ASGIApp:
    """Build the validation-only ASGI wrapper (trace=False path).

    Identical to the pre-v0.5.0 wrapper — zero tracing overhead.
    """

    async def _wrapper(scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type", "")

        if scope_type not in _KNOWN_SCOPE_TYPES:
            await app(scope, receive, send)
            return

        if exclude_paths and scope.get("path", "") in exclude_paths:
            await app(scope, receive, send)
            return

        ctx = ConnectionContext(
            scope,
            _rule_allowed=config.allows,
            _on_violation=collect,
        )
        validators = validators_by_type[scope_type]

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

    return _wrapper


def _build_traced_wrapper(
    *,
    app: ASGIApp,
    config: AsgionConfig,
    strict: bool,
    collect: ViolationCallback,
    exclude_paths: set[str],
    validators_by_type: _ValidatorMap,
    sample_rate: float,
    trace_dir: str | Path | None,
    storage: TraceStorage | None,
    max_body_size: int,
    traces_out: Inspector,
) -> ASGIApp:
    """Build the tracing + validation ASGI wrapper (trace=True path)."""
    from asgion.trace import MemoryStorage
    from asgion.trace._recorder import TraceRecorder
    from asgion.trace._sampling import _should_trace
    from asgion.trace._storage import FileStorage

    if storage is not None and trace_dir is not None:
        msg = "Cannot specify both storage= and trace_dir="
        raise TypeError(msg)

    if storage is not None:
        _storage = storage
    elif trace_dir is not None:
        _storage = FileStorage(Path(trace_dir))
    else:
        _storage = MemoryStorage()

    if isinstance(_storage, MemoryStorage):
        traces_out._traces = _storage.records  # noqa: SLF001
    else:
        traces_out._traces = []  # noqa: SLF001

    from asgion import __version__

    _version = __version__
    _max_body = max_body_size
    _rate = sample_rate
    _traces_list = traces_out._traces  # noqa: SLF001

    # Fast path wrapper for non-sampled connections (reuse the same logic)
    _fast_wrapper = _build_fast_wrapper(
        app=app,
        config=config,
        strict=strict,
        collect=collect,
        exclude_paths=exclude_paths,
        validators_by_type=validators_by_type,
    )

    async def _traced(scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type", "")

        if scope_type not in _KNOWN_SCOPE_TYPES:
            await app(scope, receive, send)
            return

        if exclude_paths and scope.get("path", "") in exclude_paths:
            await app(scope, receive, send)
            return

        if not _should_trace(_rate, scope):
            await _fast_wrapper(scope, receive, send)
            return

        recorder = TraceRecorder(
            scope, storage=_storage, max_body=_max_body, asgion_version=_version
        )

        ctx = ConnectionContext(
            scope,
            _rule_allowed=config.allows,
            _on_violation=collect,
        )
        validators = validators_by_type[scope_type]
        violation_tags: list[tuple[str, int | None]] = []

        n = len(ctx.violations)
        for v in validators:
            try:
                v.validate_scope(ctx, scope)
            except Exception:
                logger.exception("Validator %s.validate_scope() raised", type(v).__name__)
        violation_tags.extend(("scope", None) for _ in range(len(ctx.violations) - n))

        async def traced_receive() -> Message:
            message = await receive()
            try:
                recorder.on_receive(message)
            except Exception:
                logger.exception("TraceRecorder.on_receive() raised")
            event_idx = recorder.event_count - 1
            n = len(ctx.violations)
            for v in validators:
                try:
                    v.validate_receive(ctx, message)
                except Exception:
                    logger.exception("Validator %s.validate_receive() raised", type(v).__name__)
            violation_tags.extend(("receive", event_idx) for _ in range(len(ctx.violations) - n))
            return message

        async def traced_send(message: Message) -> None:
            try:
                recorder.on_send(message)
            except Exception:
                logger.exception("TraceRecorder.on_send() raised")
            event_idx = recorder.event_count - 1
            n = len(ctx.violations)
            for v in validators:
                try:
                    v.validate_send(ctx, message)
                except Exception:
                    logger.exception("Validator %s.validate_send() raised", type(v).__name__)
            violation_tags.extend(("send", event_idx) for _ in range(len(ctx.violations) - n))
            await send(message)

        try:
            await app(scope, traced_receive, traced_send)
        finally:
            n = len(ctx.violations)
            for v in validators:
                try:
                    v.validate_complete(ctx)
                except Exception:
                    logger.exception("Validator %s.validate_complete() raised", type(v).__name__)
            violation_tags.extend(("complete", None) for _ in range(len(ctx.violations) - n))

            try:
                record = recorder.finalize(ctx.violations, violation_tags)
                if not isinstance(_storage, MemoryStorage):
                    _traces_list.append(record)
            except Exception:
                logger.exception("TraceRecorder.finalize() raised")

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

    return _traced
