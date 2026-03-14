import asyncio

import pytest

from asgion import Inspector
from asgion.core.config import AsgionConfig
from tests.conftest import make_asgi_scope


async def _run_http(inspector: Inspector) -> None:
    scope = make_asgi_scope("http")
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
    scope = make_asgi_scope("http")
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
    scope = make_asgi_scope("http")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        pass

    with pytest.raises(ASGIProtocolError):
        await inspector(scope, receive, send)


async def test_violations_have_scope_index() -> None:
    """Each violation carries the scope_index of its connection."""

    async def bad_app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": "bad", "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    inspector = Inspector(bad_app)
    await _run_http(inspector)
    await _run_http(inspector)

    assert len(inspector.violations) > 0
    # First connection -> scope_index 0, second -> scope_index 1
    assert all(v.scope_index == 0 for v in inspector.violations if v.scope_index == 0)
    assert any(v.scope_index == 0 for v in inspector.violations)
    assert any(v.scope_index == 1 for v in inspector.violations)


async def test_violations_by_scope() -> None:
    """violations_by_scope groups violations by connection."""

    async def bad_app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": "bad", "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    inspector = Inspector(bad_app)
    await _run_http(inspector)
    await _run_http(inspector)

    by_scope = inspector.violations_by_scope
    assert 0 in by_scope
    assert 1 in by_scope
    # Each scope should have violations
    assert len(by_scope[0]) > 0
    assert len(by_scope[1]) > 0
    # Total should match
    assert sum(len(vs) for vs in by_scope.values()) == len(inspector.violations)


async def test_violations_by_scope_empty() -> None:
    """violations_by_scope returns empty dict when no violations."""

    async def good_app(scope, receive, send):
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": b"OK", "more_body": False})

    inspector = Inspector(good_app)
    await _run_http(inspector)
    assert inspector.violations_by_scope == {}


def test_inspector_rejects_invalid_sample_rate() -> None:
    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        pass

    with pytest.raises(ValueError, match="sample_rate"):
        Inspector(app, trace=True, sample_rate=-0.1)
    with pytest.raises(ValueError, match="sample_rate"):
        Inspector(app, trace=True, sample_rate=1.5)


def test_inspector_rejects_invalid_max_body_size() -> None:
    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        pass

    with pytest.raises(ValueError, match="max_body_size"):
        Inspector(app, trace=True, max_body_size=0)
    with pytest.raises(ValueError, match="max_body_size"):
        Inspector(app, trace=True, max_body_size=-1)


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
    scope = make_asgi_scope("http")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        pass

    await wrapped(scope, receive, send)
    assert len(violations) > 0
