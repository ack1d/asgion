import asyncio

from asgion import ASGIProtocolError, Violation, inspect
from tests.conftest import make_asgi_scope


async def _run(app, scope_type: str = "http", **kwargs) -> list[Violation]:
    violations: list[Violation] = []
    scope = make_asgi_scope(scope_type)
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

    violations = await _run(app, exclude_paths=["/"])
    assert violations == []


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

    scope = make_asgi_scope("http")
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
