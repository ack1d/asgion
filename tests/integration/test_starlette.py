"""Integration tests: asgion + Starlette."""

from collections.abc import AsyncGenerator, AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
import pytest

pytest.importorskip("starlette")

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Route

from asgion import Inspector

from ._scenarios import FrameworkTestSuite
from .conftest import CONFIG, drive_lifespan

pytestmark = pytest.mark.asgi_validate(min_severity="warning")


def _make_app() -> Starlette:
    async def hello(request: Request) -> JSONResponse:
        return JSONResponse({"hello": "world"})

    async def echo(request: Request) -> Response:
        body = await request.body()
        return Response(content=body, media_type="application/octet-stream")

    async def no_content(request: Request) -> Response:
        return Response(status_code=204)

    async def not_modified(request: Request) -> Response:
        return Response(status_code=304)

    async def redirect(request: Request) -> RedirectResponse:
        return RedirectResponse(url="/hello")

    async def stream(request: Request) -> StreamingResponse:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for chunk in [b"hello", b" ", b"world"]:
                yield chunk

        return StreamingResponse(_gen(), media_type="text/plain")

    async def empty_stream(request: Request) -> StreamingResponse:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for _ in ():
                yield b""  # pragma: no cover

        return StreamingResponse(_gen(), media_type="text/plain")

    async def custom_exception(request: Request) -> None:
        raise HTTPException(status_code=429, detail="Too Many Requests")

    async def bad_content_length(request: Request) -> Response:
        return Response(content=b"12345", headers={"Content-Length": "3"})

    async def error(request: Request) -> None:
        raise ValueError("oops")

    async def cors_bad(request: Request) -> Response:
        return Response(
            content=b"ok",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    async def many_chunks(request: Request) -> StreamingResponse:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for i in range(150):
                yield f"{i}\n".encode()

        return StreamingResponse(_gen(), media_type="text/plain")

    async def body_on_204(request: Request) -> Response:
        return Response(content=b'{"deleted": true}', status_code=204)

    async def insecure_cookie(request: Request) -> Response:
        resp = Response(content=b"ok")
        resp.set_cookie("session", "abc123", path="/")
        return resp

    return Starlette(
        routes=[
            Route("/hello", hello, methods=["GET", "HEAD"]),
            Route("/echo", echo, methods=["POST"]),
            Route("/no-content", no_content),
            Route("/not-modified", not_modified),
            Route("/redirect", redirect),
            Route("/stream", stream),
            Route("/empty-stream", empty_stream),
            Route("/custom-exception", custom_exception),
            Route("/bad-content-length", bad_content_length),
            Route("/error", error),
            Route("/cors-bad", cors_bad),
            Route("/many-chunks", many_chunks),
            Route("/body-on-204", body_on_204),
            Route("/insecure-cookie", insecure_cookie),
        ]
    )


@pytest.fixture
def raw_app() -> Starlette:
    return _make_app()


class TestStarlette(FrameworkTestSuite):
    pass


@pytest.mark.asgi_validate(exclude_rules={"SEM-003"}, min_severity="warning")
async def test_bad_content_length_detected(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    app = asgi_inspect(_make_app(), config=CONFIG)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        r = await c.get("/bad-content-length")
    assert r.status_code == 200
    assert r.content == b"12345"
    matched = [v for v in app.violations if v.rule_id == "SEM-003"]
    assert len(matched) == 1, f"Expected exactly 1 SEM-003, got: {matched}"


@pytest.mark.asgi_validate(exclude_rules={"HF-012"}, min_severity="warning")
async def test_body_on_204_detected(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    app = asgi_inspect(_make_app(), config=CONFIG)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        r = await c.get("/body-on-204")
    assert r.status_code == 204
    matched = [v for v in app.violations if v.rule_id == "HF-012"]
    assert len(matched) == 1, f"Expected exactly 1 HF-012, got: {matched}"


@pytest.mark.asgi_validate(exclude_rules={"SEM-004"}, min_severity="warning")
async def test_insecure_cookie_detected(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    app = asgi_inspect(_make_app(), config=CONFIG)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        r = await c.get("/insecure-cookie")
    assert r.status_code == 200
    matched = [v for v in app.violations if v.rule_id == "SEM-004"]
    assert len(matched) == 1, f"Expected exactly 1 SEM-004, got: {matched}"


async def test_lifespan_no_violations(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    started = False
    stopped = False

    @asynccontextmanager
    async def lifespan(starlette_app: Starlette) -> AsyncIterator[None]:
        nonlocal started, stopped
        started = True
        yield
        stopped = True

    starlette_app = Starlette(lifespan=lifespan, routes=[])
    inspected = asgi_inspect(starlette_app, config=CONFIG)

    sent = await drive_lifespan(inspected)

    assert started
    assert stopped
    sent_types = {m.get("type") for m in sent}
    assert "lifespan.startup.complete" in sent_types
    assert "lifespan.shutdown.complete" in sent_types
    assert inspected.violations == []
