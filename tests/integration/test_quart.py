"""Integration tests: asgion + Quart."""

from collections.abc import AsyncGenerator, Callable

import httpx
import pytest

pytest.importorskip("quart")

from quart import Quart, Response, abort, jsonify

from asgion import Inspector

from ._scenarios import FrameworkTestSuite
from .conftest import CONFIG, drive_lifespan

pytestmark = pytest.mark.asgi_validate(min_severity="warning")


def _make_app() -> Quart:
    app = Quart(__name__)

    @app.route("/hello", methods=["GET", "HEAD"])
    async def hello() -> Response:
        return jsonify({"hello": "world"})

    @app.route("/echo", methods=["POST"])
    async def echo() -> Response:
        from quart import request

        body = await request.get_data()
        return Response(body, content_type="application/octet-stream")

    @app.route("/no-content")
    async def no_content() -> tuple[str, int]:
        return "", 204

    @app.route("/not-modified")
    async def not_modified() -> tuple[str, int]:
        return "", 304

    @app.route("/redirect")
    async def redirect_view() -> Response:
        from quart import redirect

        return redirect("/hello")

    @app.route("/stream")
    async def stream() -> Response:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for chunk in [b"hello", b" ", b"world"]:
                yield chunk

        return Response(_gen(), content_type="text/plain")

    @app.route("/empty-stream")
    async def empty_stream() -> Response:
        async def _gen() -> AsyncGenerator[bytes, None]:
            return
            yield b""  # type: ignore[misc]  # pragma: no cover

        return Response(_gen(), content_type="text/plain")

    @app.route("/custom-exception")
    async def custom_exception() -> Response:
        abort(429)

    @app.route("/error")
    async def error_view() -> Response:
        raise ValueError("oops")

    @app.route("/cors-bad")
    async def cors_bad() -> Response:
        resp = Response(b"ok")
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/many-chunks")
    async def many_chunks() -> Response:
        async def _gen() -> AsyncGenerator[bytes, None]:
            for i in range(150):
                yield f"{i}\n".encode()

        return Response(_gen(), content_type="text/plain")

    @app.route("/body-on-204")
    async def body_on_204() -> Response:
        return Response(b'{"deleted": true}', status=204)

    @app.route("/insecure-cookie")
    async def insecure_cookie() -> Response:
        resp = Response(b"ok")
        resp.set_cookie("session", "abc123", path="/")
        return resp

    return app


@pytest.fixture
def raw_app() -> Quart:
    return _make_app()


class TestQuart(FrameworkTestSuite):
    pass


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

    app = Quart(__name__)

    @app.before_serving
    async def on_startup() -> None:
        nonlocal started
        started = True

    @app.after_serving
    async def on_shutdown() -> None:
        nonlocal stopped
        stopped = True

    inspected = asgi_inspect(app, config=CONFIG)

    sent = await drive_lifespan(inspected)

    assert started
    assert stopped
    sent_types = {m.get("type") for m in sent}
    assert "lifespan.startup.complete" in sent_types
    assert "lifespan.shutdown.complete" in sent_types
    assert inspected.violations == []
