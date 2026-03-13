"""Shared integration test scenarios.

Each framework test file inherits from these mixin classes.  The framework
file is responsible for:

- ``raw_app`` pytest fixture returning the framework ASGI application
- ``pytestmark`` for framework-specific rule exclusions

Standard endpoints that ``_make_app()`` must register:

    GET  /hello               -> 200 JSON {"hello": "world"}
    POST /echo                -> 200 echoes request body as application/octet-stream
    GET  /no-content          -> 204
    GET  /not-modified        -> 304
    GET  /redirect            -> 3xx -> /hello
    GET  /stream              -> 200 streaming "hello world" (3 chunks)
    GET  /empty-stream        -> 200 streaming (0 chunks)
    GET  /custom-exception    -> 429
    GET  /error               -> 500 (unhandled ValueError)
    GET  /cors-bad            -> 200 with Access-Control-Allow-Origin: *
                                      and Access-Control-Allow-Credentials: true
    GET  /many-chunks         -> 200 streaming 150 tiny chunks
    GET  /insecure-cookie     -> 200 with Set-Cookie without Secure flag
    GET  /body-on-204         -> 204 with non-empty body (intentional violation)

Lifespan and framework-specific detection tests are standalone functions, not mixins.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from asgion import Inspector


class HappyPathTests:
    async def test_get_json(self, client: Any) -> None:
        r = await client.get("/hello")
        assert r.status_code == 200
        assert r.json() == {"hello": "world"}
        assert r.headers["content-type"].startswith("application/json")

    async def test_404(self, client: Any) -> None:
        r = await client.get("/not-found")
        assert r.status_code == 404

    async def test_post_with_body(self, client: Any) -> None:
        payload = b"ping pong"
        r = await client.post("/echo", content=payload)
        assert r.status_code == 200
        assert r.content == payload
        assert r.headers["content-type"] == "application/octet-stream"

    async def test_custom_exception(self, client: Any) -> None:
        r = await client.get("/custom-exception")
        assert r.status_code == 429

    async def test_server_error_500(self, client: Any) -> None:
        r = await client.get("/error")
        assert r.status_code == 500


class StatusCodeTests:
    async def test_no_content_204(self, client: Any) -> None:
        r = await client.get("/no-content")
        assert r.status_code == 204
        assert r.content == b""

    async def test_not_modified_304(self, client: Any) -> None:
        r = await client.get("/not-modified")
        assert r.status_code == 304
        assert r.content == b""


class MethodTests:
    async def test_head_request(self, client: Any) -> None:
        r = await client.head("/hello")
        assert r.status_code == 200
        assert r.content == b""


class StreamingTests:
    async def test_streaming_response(self, client: Any) -> None:
        r = await client.get("/stream")
        assert r.status_code == 200
        assert r.text == "hello world"
        assert r.headers["content-type"].startswith("text/plain")

    async def test_empty_streaming_response(self, client: Any) -> None:
        r = await client.get("/empty-stream")
        assert r.status_code == 200
        assert r.text == ""


class RedirectTests:
    async def test_redirect_no_follow(self, client: Any) -> None:
        r = await client.get("/redirect", follow_redirects=False)
        assert 300 <= r.status_code < 400

    async def test_redirect_follow(self, client: Any) -> None:
        r = await client.get("/redirect", follow_redirects=True)
        assert r.status_code == 200
        assert r.json() == {"hello": "world"}


class StateIsolationTests:
    async def test_multiple_requests_no_state_leak(self, client: Any) -> None:
        for _ in range(3):
            r = await client.get("/hello")
            assert r.status_code == 200

    async def test_concurrent_requests(self, client: Any) -> None:
        results = await asyncio.gather(
            client.get("/hello"),
            client.post("/echo", content=b"concurrent"),
            client.get("/hello"),
        )
        assert results[0].status_code == 200
        assert results[1].status_code == 200
        assert results[1].content == b"concurrent"
        assert results[2].status_code == 200


class DetectionCORSTests:
    # min_severity="error" on teardown so other WARNING-level violations don't fail the test.
    @pytest.mark.asgi_validate(min_severity="error")
    async def test_cors_wildcard_credentials_detected(self, client: Any, app: Inspector) -> None:
        r = await client.get("/cors-bad")
        assert r.status_code == 200
        matched = [v for v in app.violations if v.rule_id == "SEM-012"]
        assert len(matched) == 1, f"Expected exactly 1 SEM-012, got: {matched}"


class DetectionChunkTests:
    # SEM-011 is INFO — needs strict profile to be visible.
    @pytest.mark.asgi_validate(min_severity="error")
    async def test_excessive_chunking_detected(
        self, client_strict: Any, app_strict: Inspector
    ) -> None:
        r = await client_strict.get("/many-chunks")
        assert r.status_code == 200
        matched = [v for v in app_strict.violations if v.rule_id == "SEM-011"]
        assert len(matched) == 1, f"Expected exactly 1 SEM-011, got: {matched}"


class FrameworkTestSuite(
    HappyPathTests,
    StatusCodeTests,
    MethodTests,
    StreamingTests,
    RedirectTests,
    StateIsolationTests,
    DetectionCORSTests,
    DetectionChunkTests,
):
    pass
