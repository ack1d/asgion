"""Integration tests: asgion + Django ASGI."""

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest

pytest.importorskip("django")

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        ROOT_URLCONF=__name__,
        SECRET_KEY="test-secret-key",  # noqa: S106
        ALLOWED_HOSTS=["*"],
        DEBUG=False,
    )
    django.setup()

from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.urls import path

from asgion import Inspector

from ._scenarios import FrameworkTestSuite
from .conftest import CONFIG

# Django sends mixed-case header names — exclude HE-009 from teardown checks.
pytestmark = pytest.mark.asgi_validate(min_severity="warning", exclude_rules={"HE-009"})


async def hello(request):  # type: ignore[no-untyped-def]
    return JsonResponse({"hello": "world"})


async def echo(request):  # type: ignore[no-untyped-def]
    return HttpResponse(content=request.body, content_type="application/octet-stream")


async def no_content(request):  # type: ignore[no-untyped-def]
    return HttpResponse(status=204)


async def not_modified(request):  # type: ignore[no-untyped-def]
    return HttpResponse(status=304)


async def redirect_view(request):  # type: ignore[no-untyped-def]
    return HttpResponseRedirect("/hello")


async def stream(request):  # type: ignore[no-untyped-def]
    async def _gen() -> AsyncIterator[bytes]:
        for chunk in [b"hello", b" ", b"world"]:
            yield chunk

    return StreamingHttpResponse(_gen(), content_type="text/plain")


async def empty_stream(request):  # type: ignore[no-untyped-def]
    async def _gen() -> AsyncIterator[bytes]:
        return
        yield b""  # type: ignore[misc]  # pragma: no cover

    return StreamingHttpResponse(_gen(), content_type="text/plain")


async def custom_exception(request):  # type: ignore[no-untyped-def]
    return HttpResponse("Too Many Requests", status=429)


async def error_view(request):  # type: ignore[no-untyped-def]
    raise ValueError("oops")


async def cors_bad(request):  # type: ignore[no-untyped-def]
    resp = HttpResponse(b"ok")
    resp["Access-Control-Allow-Origin"] = "*"
    resp["Access-Control-Allow-Credentials"] = "true"
    return resp


async def many_chunks(request):  # type: ignore[no-untyped-def]
    async def _gen() -> AsyncIterator[bytes]:
        for i in range(150):
            yield f"{i}\n".encode()

    return StreamingHttpResponse(_gen(), content_type="text/plain")


async def insecure_cookie(request):  # type: ignore[no-untyped-def]
    resp = HttpResponse(b"ok")
    resp.set_cookie("session", "abc123", path="/")
    return resp


async def body_on_204(request):  # type: ignore[no-untyped-def]
    return HttpResponse(content=b'{"deleted": true}', status=204)


urlpatterns = [
    path("hello", hello),
    path("echo", echo),
    path("no-content", no_content),
    path("not-modified", not_modified),
    path("redirect", redirect_view),
    path("stream", stream),
    path("empty-stream", empty_stream),
    path("custom-exception", custom_exception),
    path("error", error_view),
    path("cors-bad", cors_bad),
    path("many-chunks", many_chunks),
    path("insecure-cookie", insecure_cookie),
    path("body-on-204", body_on_204),
]


def _make_app():  # type: ignore[no-untyped-def]
    from django.core.asgi import get_asgi_application

    return get_asgi_application()


@pytest.fixture
def raw_app() -> Any:
    return _make_app()


class TestDjango(FrameworkTestSuite):
    pass


@pytest.mark.asgi_validate(exclude_rules={"HE-009", "SEM-004"}, min_severity="warning")
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


@pytest.mark.asgi_validate(exclude_rules={"HE-009", "HF-012"}, min_severity="warning")
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


@pytest.mark.asgi_validate(exclude_rules={"HE-009"}, min_severity="warning")
async def test_mixed_case_headers_detected(
    asgi_inspect: Callable[..., Inspector],
) -> None:
    app = asgi_inspect(_make_app(), config=CONFIG)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        await c.get("/hello")
    matched = [v for v in app.violations if v.rule_id == "HE-009"]
    assert len(matched) >= 1, f"Expected HE-009, got: {[v.rule_id for v in app.violations]}"
