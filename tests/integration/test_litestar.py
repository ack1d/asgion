"""Integration tests: asgion + Litestar 2.x."""

from collections.abc import AsyncGenerator, Callable
from typing import Any

import httpx
import pytest

pytest.importorskip("litestar")

from litestar import Litestar, Response, get, head, post
from litestar.exceptions import HTTPException
from litestar.response import Redirect, Stream

from asgion import Inspector

from ._scenarios import FrameworkTestSuite
from .conftest import CONFIG, drive_lifespan

pytestmark = pytest.mark.asgi_validate(min_severity="warning")


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
        raise HTTPException(status_code=429, detail="Too Many Requests")

    @get("/error")
    async def error() -> None:
        raise ValueError("oops")

    @get("/cors-bad")
    async def cors_bad() -> Response[Any]:
        return Response(
            content=b"ok",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    @get("/many-chunks")
    async def many_chunks() -> Stream:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for i in range(150):
                yield f"{i}\n".encode()

        return Stream(_gen(), media_type="text/plain")

    @get("/insecure-cookie")
    async def insecure_cookie() -> Response[Any]:
        resp = Response(content=b"ok")
        resp.set_cookie("session", "abc123", path="/")
        return resp

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
            cors_bad,
            many_chunks,
            insecure_cookie,
        ]
    )


@pytest.fixture
def raw_app() -> Litestar:
    return _make_app()


class TestLitestar(FrameworkTestSuite):
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


def test_body_on_204_rejected_by_framework() -> None:
    """Litestar rejects 204-with-body at route registration time."""
    from litestar.exceptions import ImproperlyConfiguredException

    @get("/body-on-204", status_code=204)
    async def body_on_204() -> Response[Any]:
        return Response(content=b'{"deleted": true}', status_code=204)

    with pytest.raises(ImproperlyConfiguredException):
        Litestar(route_handlers=[body_on_204])


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
    inspected = asgi_inspect(litestar_app, config=CONFIG)

    sent = await drive_lifespan(inspected)

    assert started
    assert stopped
    sent_types = {m.get("type") for m in sent}
    assert "lifespan.startup.complete" in sent_types
    assert "lifespan.shutdown.complete" in sent_types
    assert inspected.violations == []
