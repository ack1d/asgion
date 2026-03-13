"""Integration tests: asgion + FastAPI."""

from collections.abc import AsyncGenerator, AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, StreamingResponse

from asgion import Inspector

from ._scenarios import FrameworkTestSuite
from .conftest import CONFIG, drive_lifespan

pytestmark = pytest.mark.asgi_validate(min_severity="warning")


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
        raise HTTPException(status_code=429, detail="Too Many Requests")

    @api.get("/error")
    async def error() -> None:
        raise ValueError("oops")

    @api.get("/cors-bad")
    async def cors_bad() -> Response:
        return Response(
            content=b"ok",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    @api.get("/many-chunks")
    async def many_chunks() -> StreamingResponse:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for i in range(150):
                yield f"{i}\n".encode()

        return StreamingResponse(_gen(), media_type="text/plain")

    @api.get("/body-on-204", status_code=204)
    async def body_on_204() -> Response:
        return Response(content=b'{"deleted": true}', status_code=204)

    @api.get("/insecure-cookie")
    async def insecure_cookie() -> Response:
        resp = Response(content=b"ok")
        resp.set_cookie("session", "abc123", path="/")
        return resp

    return api


@pytest.fixture
def raw_app() -> FastAPI:
    return _make_app()


class TestFastAPI(FrameworkTestSuite):
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
    async def lifespan(api: FastAPI) -> AsyncIterator[None]:
        nonlocal started, stopped
        started = True
        yield
        stopped = True

    api = FastAPI(lifespan=lifespan)
    inspected = asgi_inspect(api, config=CONFIG)

    sent = await drive_lifespan(inspected)

    assert started
    assert stopped
    sent_types = {m.get("type") for m in sent}
    assert "lifespan.startup.complete" in sent_types
    assert "lifespan.shutdown.complete" in sent_types
    assert inspected.violations == []
