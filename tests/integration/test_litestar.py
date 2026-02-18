"""Integration tests: asgion + Litestar 2.x."""

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator, Callable
from typing import Any

import pytest

pytest.importorskip("litestar")

from litestar import Litestar, Response, get, head, post
from litestar.exceptions import HTTPException
from litestar.response import Redirect, Stream
from litestar.testing import AsyncTestClient

from asgion import BUILTIN_PROFILES
from asgion.pytest_plugin import InspectedApp

_CONFIG = BUILTIN_PROFILES["recommended"]

# G-011/LS-002: AsyncTestClient omits the 'asgi' version dict from scope —
# a test-client limitation, not a Litestar application violation.
pytestmark = pytest.mark.asgi_validate(exclude_rules={"G-011", "LS-002"}, min_severity="warning")


# App


def _make_app() -> Litestar:
    @get("/hello")
    async def hello() -> dict[str, str]:
        return {"hello": "world"}

    @head("/hello")
    async def hello_head() -> None:
        return None

    @get("/no-content", status_code=204)
    async def no_content() -> None:
        return None

    @get("/not-modified", status_code=304)
    async def not_modified() -> None:
        return None

    @post("/echo", status_code=200)
    async def echo(request: Any) -> Response[Any]:
        body = await request.body()
        return Response(content=body, media_type="application/octet-stream")

    @get("/stream")
    async def stream() -> Stream:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for chunk in [b"hello", b" ", b"world"]:
                yield chunk

        return Stream(_gen(), media_type="text/plain")

    @get("/empty-stream")
    async def empty_stream() -> Stream:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for _ in ():
                yield b""  # pragma: no cover

        return Stream(_gen(), media_type="text/plain")

    @get("/redirect")
    async def redirect() -> Redirect:
        return Redirect(path="/hello")

    @get("/bad-content-length")
    async def bad_content_length() -> Response[Any]:
        return Response(
            content=b"12345",
            media_type="text/plain",
            headers={"Content-Length": "3"},
        )

    @get("/custom-exception")
    async def custom_exception() -> None:
        raise HTTPException(status_code=418, detail="I'm a teapot")

    @get("/error")
    async def error() -> None:
        raise ValueError("oops")

    return Litestar(
        route_handlers=[
            hello,
            hello_head,
            no_content,
            not_modified,
            echo,
            stream,
            empty_stream,
            redirect,
            bad_content_length,
            custom_exception,
            error,
        ]
    )


# Fixtures


@pytest.fixture
def app(asgi_inspect: Callable[..., InspectedApp]) -> InspectedApp:
    return asgi_inspect(_make_app(), config=_CONFIG)


@pytest.fixture
async def client(app: InspectedApp) -> AsyncIterator[AsyncTestClient[Any]]:
    async with AsyncTestClient(app=app) as c:  # type: ignore[type-var]
        yield c


# Tests — Happy Path


async def test_get_json(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/hello")
    assert r.status_code == 200
    assert r.json() == {"hello": "world"}
    assert r.headers["content-type"].startswith("application/json")


async def test_404(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/not-found")
    assert r.status_code == 404


async def test_post_with_body(client: AsyncTestClient[Any]) -> None:
    payload = b"ping pong"
    r = await client.post("/echo", content=payload)
    assert r.status_code == 200
    assert r.content == payload
    assert r.headers["content-type"] == "application/octet-stream"


async def test_custom_exception(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/custom-exception")
    assert r.status_code == 418


async def test_server_error_500(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/error")
    assert r.status_code == 500


# Tests — Status Code Semantics


async def test_no_content_204(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/no-content")
    assert r.status_code == 204
    assert r.content == b""


async def test_not_modified_304(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/not-modified")
    assert r.status_code == 304
    assert r.content == b""


# Tests — Method Semantics


async def test_head_request(client: AsyncTestClient[Any]) -> None:
    r = await client.head("/hello")
    assert r.status_code == 200
    assert r.content == b""


# Tests — Streaming


async def test_streaming_response(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/stream")
    assert r.status_code == 200
    assert r.text == "hello world"
    assert r.headers["content-type"].startswith("text/plain")


async def test_empty_streaming_response(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/empty-stream")
    assert r.status_code == 200
    assert r.text == ""


# Tests — Redirects


async def test_redirect(client: AsyncTestClient[Any]) -> None:
    r = await client.get("/redirect", follow_redirects=True)
    assert r.status_code == 200
    assert r.json() == {"hello": "world"}


# Tests — Detection (violations expected)


@pytest.mark.asgi_validate(exclude_rules={"G-011", "LS-002", "SEM-003"}, min_severity="warning")
async def test_bad_content_length_detected(client: AsyncTestClient[Any], app: InspectedApp) -> None:
    r = await client.get("/bad-content-length")
    assert r.status_code == 200
    assert r.content == b"12345"
    rule_ids = {v.rule_id for v in app.violations}
    assert "SEM-003" in rule_ids, f"Expected SEM-003, got: {rule_ids}"


# Tests — State Isolation


async def test_multiple_requests_no_state_leak(client: AsyncTestClient[Any]) -> None:
    for _ in range(3):
        r = await client.get("/hello")
        assert r.status_code == 200


async def test_concurrent_requests(client: AsyncTestClient[Any]) -> None:
    results = await asyncio.gather(
        client.get("/hello"),
        client.post("/echo", content=b"concurrent"),
        client.get("/hello"),
    )
    assert results[0].status_code == 200
    assert results[1].status_code == 200
    assert results[1].content == b"concurrent"
    assert results[2].status_code == 200


# Tests — Lifespan


async def test_lifespan_no_violations(
    asgi_inspect: Callable[..., InspectedApp],
) -> None:
    started = False
    stopped = False

    async def on_startup() -> None:
        nonlocal started
        started = True

    async def on_shutdown() -> None:
        nonlocal stopped
        stopped = True

    litestar_app = Litestar(
        route_handlers=[],
        on_startup=[on_startup],
        on_shutdown=[on_shutdown],
    )
    inspected = asgi_inspect(litestar_app, config=_CONFIG)

    async with AsyncTestClient(app=inspected) as _:  # type: ignore[type-var]
        assert started

    assert stopped
    # Filter out G-011/LS-002: AsyncTestClient doesn't include the 'asgi' dict in scope.
    app_violations = [v for v in inspected.violations if v.rule_id not in {"G-011", "LS-002"}]
    assert app_violations == []
