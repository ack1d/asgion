import asyncio

import pytest

from asgion import ASGIProtocolError, Violation, inspect


def _make_scope(scope_type: str = "http") -> dict:
    if scope_type == "http":
        return {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "path": "/test",
            "query_string": b"",
            "root_path": "",
            "headers": [],
        }
    if scope_type == "websocket":
        return {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "ws",
            "path": "/ws",
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "subprotocols": [],
        }
    return {"type": scope_type, "asgi": {"version": "3.0"}}


async def _run(app, scope_type: str = "http", **kwargs) -> list[Violation]:
    violations: list[Violation] = []
    scope = _make_scope(scope_type)
    request_sent = False

    async def receive():
        nonlocal request_sent
        if scope_type == "http":
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.sleep(999)
            return {"type": "http.disconnect"}
        if scope_type == "websocket":
            if not request_sent:
                request_sent = True
                return {"type": "websocket.connect"}
            await asyncio.sleep(999)
            return {"type": "websocket.disconnect", "code": 1000}
        if scope_type == "lifespan":
            if not request_sent:
                request_sent = True
                return {"type": "lifespan.startup"}
            await asyncio.sleep(999)
            return {"type": "lifespan.shutdown"}
        return {}  # pragma: no cover

    async def send(msg):
        pass

    wrapped = inspect(app, on_violation=violations.append, **kwargs)
    try:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=2.0)
    except (TimeoutError, ASGIProtocolError):
        pass
    return violations


async def test_correct_http_app_no_violations():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    violations = await _run(app)
    assert violations == []


async def test_unknown_scope_type_passes_through():
    called = False

    async def app(scope, receive, send):
        nonlocal called
        called = True

    scope = {"type": "ftp"}

    async def receive():
        return {}  # pragma: no cover

    async def send(msg):
        pass  # pragma: no cover

    wrapped = inspect(app)
    await wrapped(scope, receive, send)
    assert called


async def test_exclude_paths():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.body", "body": b"oops"})

    violations = await _run(app, exclude_paths=["/test"])
    assert violations == []


async def test_on_violation_callback_fires():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": "bad", "headers": []})
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    violations = await _run(app)
    assert len(violations) > 0
    assert any(v.rule_id == "HE-011" for v in violations)


async def test_strict_mode_raises():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "headers": []})
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    scope = _make_scope("http")
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(999)
        return {"type": "http.disconnect"}

    async def send(msg):
        pass

    wrapped = inspect(app, strict=True)
    with pytest.raises(ASGIProtocolError) as exc_info:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=2.0)
    assert len(exc_info.value.violations) > 0


async def test_exclude_rules_suppresses():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 999, "headers": []})
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    violations = await _run(app, exclude_rules={"HE-012"})
    assert not any(v.rule_id == "HE-012" for v in violations)


async def test_events_are_recorded():
    from asgion.core.context import ConnectionContext
    from asgion.validators.base import create_default_registry

    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    from asgion.validators.base import BaseValidator

    captured_ctx: list[ConnectionContext] = []

    class ContextCapture(BaseValidator):
        def validate_complete(self, ctx: ConnectionContext) -> None:
            captured_ctx.append(ctx)

    registry = create_default_registry()
    registry.register(ContextCapture())

    scope = _make_scope("http")
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(999)
        return {"type": "http.disconnect"}

    async def send(msg):
        pass

    wrapped = inspect(app, registry=registry)
    try:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=2.0)
    except TimeoutError:
        pass

    assert len(captured_ctx) == 1
    ctx = captured_ctx[0]
    assert len(ctx.events) == 3
    assert ctx.events[0]["phase"] == "receive"
    assert ctx.events[0]["type"] == "http.request"
    assert ctx.events[1]["phase"] == "send"
    assert ctx.events[1]["type"] == "http.response.start"
    assert ctx.events[2]["phase"] == "send"
    assert ctx.events[2]["type"] == "http.response.body"
    for event in ctx.events:
        assert "t" in event
        assert event["t"] >= 0


async def test_websocket_through_wrapper():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.send", "bytes": b"hi", "text": None})
        await send({"type": "websocket.close", "code": 1000})

    violations = await _run(app, scope_type="websocket")
    assert violations == []


async def test_lifespan_through_wrapper():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.complete"})

    scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
    msgs = iter(
        [
            {"type": "lifespan.startup"},
            {"type": "lifespan.shutdown"},
        ]
    )

    async def receive():
        try:
            return next(msgs)
        except StopIteration:
            await asyncio.sleep(999)
            return {}

    async def send(msg):
        pass

    violations: list[Violation] = []
    wrapped = inspect(app, on_violation=violations.append)
    try:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=2.0)
    except TimeoutError:
        pass
    assert violations == []


async def test_validator_exception_does_not_crash_app():
    from asgion.validators.base import BaseValidator, ValidatorRegistry

    class BrokenValidator(BaseValidator):
        def validate_send(self, ctx, message):
            msg = "intentional test error"
            raise RuntimeError(msg)

    registry = ValidatorRegistry()
    registry.register(BrokenValidator())

    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    scope = _make_scope("http")
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(999)
        return {"type": "http.disconnect"}

    sent_messages: list[dict] = []

    async def send(msg):
        sent_messages.append(msg)

    wrapped = inspect(app, registry=registry)
    try:
        await asyncio.wait_for(wrapped(scope, receive, send), timeout=2.0)
    except TimeoutError:
        pass

    assert len(sent_messages) == 2
