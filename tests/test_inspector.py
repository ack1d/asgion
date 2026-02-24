import asyncio

import pytest

from asgion import Inspector
from asgion.core.config import AsgionConfig


def _make_scope(scope_type: str = "http") -> dict:
    if scope_type == "http":
        return {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/test",
            "raw_path": b"/test",
            "query_string": b"",
            "root_path": "",
            "headers": [],
        }
    return {"type": scope_type, "asgi": {"version": "3.0"}}


async def _run_http(inspector: Inspector) -> None:
    scope = _make_scope("http")
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(999)
        return {}

    async def send(msg):
        pass

    try:
        await asyncio.wait_for(inspector(scope, receive, send), timeout=2.0)
    except TimeoutError:
        pass


async def test_inspector_no_violations_on_valid_app() -> None:
    async def app(scope, receive, send):
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    inspector = Inspector(app)
    await _run_http(inspector)
    assert inspector.violations == []


async def test_inspector_collects_violations() -> None:
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": "bad", "headers": []})
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    inspector = Inspector(app)
    await _run_http(inspector)
    assert len(inspector.violations) > 0
    assert any(v.rule_id == "HE-006" for v in inspector.violations)


async def test_inspector_accumulates_across_connections() -> None:
    """Violations from multiple connections all appear in inspector.violations."""

    async def bad_app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": "bad", "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    inspector = Inspector(bad_app)
    await _run_http(inspector)
    count_after_first = len(inspector.violations)
    assert count_after_first > 0

    await _run_http(inspector)
    assert len(inspector.violations) > count_after_first


async def test_inspector_asgi_app_attribute() -> None:
    async def app(scope, receive, send):
        pass

    inspector = Inspector(app)
    assert callable(inspector.asgi_app)


async def test_inspector_is_callable_as_asgi_app() -> None:
    async def app(scope, receive, send):
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    inspector = Inspector(app)
    # Inspector itself must be callable (ASGI app interface)
    scope = _make_scope("http")
    sent_flag = False

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        nonlocal sent_flag
        sent_flag = True

    await inspector(scope, receive, send)
    assert sent_flag


async def test_inspector_on_violation_callback_fires() -> None:
    collected = []

    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": "bad", "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    inspector = Inspector(app, on_violation=collected.append)
    await _run_http(inspector)
    # Both inspector.violations and external callback must receive the same items
    assert len(collected) > 0
    assert len(inspector.violations) == len(collected)


async def test_inspector_exclude_rules() -> None:
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 999, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    inspector = Inspector(app, exclude_rules={"HE-007"})
    await _run_http(inspector)
    assert not any(v.rule_id == "HE-007" for v in inspector.violations)


async def test_inspector_with_config() -> None:
    cfg = AsgionConfig(min_severity="error")

    async def app(scope, receive, send):
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    inspector = Inspector(app, config=cfg)
    await _run_http(inspector)
    assert all(v.severity == "error" for v in inspector.violations)


async def test_inspector_strict_raises() -> None:
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    from asgion import ASGIProtocolError

    inspector = Inspector(app, strict=True)
    scope = _make_scope("http")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        pass

    with pytest.raises(ASGIProtocolError):
        await inspector(scope, receive, send)


async def test_inspect_function_still_works() -> None:
    """inspect() returns a plain ASGI callable; backward compatible."""
    from asgion import inspect

    violations = []

    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": "bad", "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    wrapped = inspect(app, on_violation=violations.append)
    assert callable(wrapped)
    await _run_http(Inspector(app))  # just ensure no error
    scope = _make_scope("http")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        pass

    await wrapped(scope, receive, send)
    assert len(violations) > 0
