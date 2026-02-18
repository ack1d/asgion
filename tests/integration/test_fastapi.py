"""Integration tests: asgion + FastAPI."""

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, StreamingResponse

from asgion import BUILTIN_PROFILES
from asgion.pytest_plugin import InspectedApp

from .conftest import drive_lifespan

_CONFIG = BUILTIN_PROFILES["recommended"]

pytestmark = pytest.mark.asgi_validate(min_severity="warning")


# App


def _make_app() -> FastAPI:
    api = FastAPI()

    @api.api_route("/hello", methods=["GET", "HEAD"])
    async def hello() -> dict[str, str]:
        return {"hello": "world"}

    @api.get("/no-content", status_code=204)
    async def no_content() -> None:
        return None

    @api.get("/not-modified", status_code=304)
    async def not_modified() -> None:
        return None

    @api.post("/echo")
    async def echo(request: Request) -> Response:
        body = await request.body()
        return Response(content=body, media_type="application/octet-stream")

    @api.get("/stream")
    async def stream() -> StreamingResponse:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for chunk in [b"hello", b" ", b"world"]:
                yield chunk

        return StreamingResponse(_gen(), media_type="text/plain")

    @api.get("/empty-stream")
    async def empty_stream() -> StreamingResponse:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for _ in ():
                yield b""  # pragma: no cover

        return StreamingResponse(_gen(), media_type="text/plain")

    @api.get("/redirect")
    async def redirect() -> RedirectResponse:
        return RedirectResponse(url="/hello")

    @api.get("/bad-content-length")
    async def bad_content_length() -> Response:
        return Response(content=b"12345", headers={"Content-Length": "3"})

    @api.get("/custom-exception")
    async def custom_exception() -> None:
        raise HTTPException(status_code=418, detail="I'm a teapot")

    @api.get("/error")
    async def error() -> None:
        raise ValueError("oops")

    return api


# Fixtures


@pytest.fixture
def app(asgi_inspect: Callable[..., InspectedApp]) -> InspectedApp:
    return asgi_inspect(_make_app(), config=_CONFIG)


@pytest.fixture
async def client(app: InspectedApp) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


# Tests — Happy Path


async def test_get_json(client: httpx.AsyncClient) -> None:
    r = await client.get("/hello")
    assert r.status_code == 200
    assert r.json() == {"hello": "world"}
    assert r.headers["content-type"].startswith("application/json")


async def test_404(client: httpx.AsyncClient) -> None:
    r = await client.get("/not-found")
    assert r.status_code == 404


async def test_post_with_body(client: httpx.AsyncClient) -> None:
    payload = b"ping pong"
    r = await client.post("/echo", content=payload)
    assert r.status_code == 200
    assert r.content == payload
    assert r.headers["content-type"] == "application/octet-stream"


async def test_custom_exception(client: httpx.AsyncClient) -> None:
    r = await client.get("/custom-exception")
    assert r.status_code == 418
    assert r.json()["detail"] == "I'm a teapot"


async def test_server_error_500(client: httpx.AsyncClient) -> None:
    r = await client.get("/error")
    assert r.status_code == 500


# Tests — Status Code Semantics


async def test_no_content_204(client: httpx.AsyncClient) -> None:
    r = await client.get("/no-content")
    assert r.status_code == 204
    assert r.content == b""


async def test_not_modified_304(client: httpx.AsyncClient) -> None:
    r = await client.get("/not-modified")
    assert r.status_code == 304
    assert r.content == b""


# ---------------------------------------------------------------------------
# Tests — Method Semantics
# ---------------------------------------------------------------------------


async def test_head_request(client: httpx.AsyncClient) -> None:
    r = await client.head("/hello")
    assert r.status_code == 200
    assert r.content == b""


# Tests — Streaming


async def test_streaming_response(client: httpx.AsyncClient) -> None:
    r = await client.get("/stream")
    assert r.status_code == 200
    assert r.text == "hello world"
    assert r.headers["content-type"].startswith("text/plain")


async def test_empty_streaming_response(client: httpx.AsyncClient) -> None:
    r = await client.get("/empty-stream")
    assert r.status_code == 200
    assert r.text == ""


# Tests — Redirects


async def test_redirect(client: httpx.AsyncClient) -> None:
    r = await client.get("/redirect", follow_redirects=True)
    assert r.status_code == 200
    assert r.json() == {"hello": "world"}


# Tests — Detection (violations expected)


@pytest.mark.asgi_validate(exclude_rules={"SEM-003"}, min_severity="warning")
async def test_bad_content_length_detected(client: httpx.AsyncClient, app: InspectedApp) -> None:
    r = await client.get("/bad-content-length")
    assert r.status_code == 200
    assert r.content == b"12345"
    rule_ids = {v.rule_id for v in app.violations}
    assert "SEM-003" in rule_ids, f"Expected SEM-003, got: {rule_ids}"


# Tests — State Isolation


async def test_multiple_requests_no_state_leak(client: httpx.AsyncClient) -> None:
    for _ in range(3):
        r = await client.get("/hello")
        assert r.status_code == 200


async def test_concurrent_requests(client: httpx.AsyncClient) -> None:
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

    @asynccontextmanager
    async def lifespan(api: FastAPI) -> AsyncIterator[None]:
        nonlocal started, stopped
        started = True
        yield
        stopped = True

    api = FastAPI(lifespan=lifespan)
    app = asgi_inspect(api, config=_CONFIG)

    sent = await drive_lifespan(app)

    assert started
    assert stopped
    sent_types = {m.get("type") for m in sent}
    assert "lifespan.startup.complete" in sent_types
    assert "lifespan.shutdown.complete" in sent_types
