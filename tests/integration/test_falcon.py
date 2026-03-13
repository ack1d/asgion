"""Integration tests: asgion + Falcon ASGI."""

from collections.abc import AsyncIterator, Callable

import httpx
import pytest

pytest.importorskip("falcon")

import falcon.asgi

from asgion import Inspector

from ._scenarios import FrameworkTestSuite
from .conftest import CONFIG, drive_lifespan

pytestmark = pytest.mark.asgi_validate(min_severity="warning")


class HelloResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.media = {"hello": "world"}

    async def on_head(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.content_type = "application/json"


class EchoResource:
    async def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        body = await req.bounded_stream.read()
        resp.data = body
        resp.content_type = "application/octet-stream"


class NoContentResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.status = 204


class NotModifiedResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.status = 304


class RedirectResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        raise falcon.HTTPTemporaryRedirect("/hello")


class StreamResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        async def _gen() -> AsyncIterator[bytes]:
            for chunk in [b"hello", b" ", b"world"]:
                yield chunk

        resp.content_type = "text/plain"
        resp.stream = _gen()


class EmptyStreamResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        async def _gen() -> AsyncIterator[bytes]:
            return
            yield b""  # type: ignore[misc]  # pragma: no cover

        resp.content_type = "text/plain"
        resp.stream = _gen()


class CustomExceptionResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        raise falcon.HTTPError(429, title="Too Many Requests")


class ErrorResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        raise ValueError("oops")


class CORSBadResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.data = b"ok"
        resp.set_header("Access-Control-Allow-Origin", "*")
        resp.set_header("Access-Control-Allow-Credentials", "true")


class ManyChunksResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        async def _gen() -> AsyncIterator[bytes]:
            for i in range(150):
                yield f"{i}\n".encode()

        resp.content_type = "text/plain"
        resp.stream = _gen()


class InsecureCookieResource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.data = b"ok"
        resp.set_cookie("session", "abc123", path="/")


class BodyOn204Resource:
    async def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.status = 204
        resp.data = b'{"deleted": true}'


def _make_app() -> falcon.asgi.App:
    app = falcon.asgi.App()
    app.add_route("/hello", HelloResource())
    app.add_route("/echo", EchoResource())
    app.add_route("/no-content", NoContentResource())
    app.add_route("/not-modified", NotModifiedResource())
    app.add_route("/redirect", RedirectResource())
    app.add_route("/stream", StreamResource())
    app.add_route("/empty-stream", EmptyStreamResource())
    app.add_route("/custom-exception", CustomExceptionResource())
    app.add_route("/error", ErrorResource())
    app.add_route("/cors-bad", CORSBadResource())
    app.add_route("/many-chunks", ManyChunksResource())
    app.add_route("/insecure-cookie", InsecureCookieResource())
    app.add_route("/body-on-204", BodyOn204Resource())
    return app


@pytest.fixture
def raw_app() -> falcon.asgi.App:
    return _make_app()


class TestFalcon(FrameworkTestSuite):
    pass


@pytest.mark.asgi_validate(exclude_rules={"SEM-004"}, min_severity="warning")
async def test_insecure_cookie_not_detected(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    """Same set_cookie() code as other frameworks, but Falcon adds Secure by default."""
    app = asgi_inspect(_make_app(), config=CONFIG)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        r = await c.get("/insecure-cookie")
    assert r.status_code == 200
    matched = [v for v in app.violations if v.rule_id == "SEM-004"]
    assert matched == [], f"Falcon adds Secure by default, expected no SEM-004, got: {matched}"


async def test_body_on_204_not_detected(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    """Same body-on-204 code as other frameworks, but Falcon strips the body."""
    app = asgi_inspect(_make_app(), config=CONFIG)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        r = await c.get("/body-on-204")
    assert r.status_code == 204
    matched = [v for v in app.violations if v.rule_id == "HF-012"]
    assert matched == [], f"Falcon strips body on 204, expected no HF-012, got: {matched}"


async def test_lifespan_no_violations(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    started = False
    stopped = False

    class LifespanMiddleware:
        async def process_startup(self, scope: object, event: object) -> None:
            nonlocal started
            started = True

        async def process_shutdown(self, scope: object, event: object) -> None:
            nonlocal stopped
            stopped = True

    app = falcon.asgi.App(middleware=[LifespanMiddleware()])
    inspected = asgi_inspect(app, config=CONFIG)

    sent = await drive_lifespan(inspected)

    assert started
    assert stopped
    sent_types = {m.get("type") for m in sent}
    assert "lifespan.startup.complete" in sent_types
    assert "lifespan.shutdown.complete" in sent_types
    assert inspected.violations == []
