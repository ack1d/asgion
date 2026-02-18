"""End-to-end detection tests.

Complements unit tests (test_http_fsm.py, test_semantic.py, …) which call
validators directly.  Here we verify that the full inspect() pipeline — scope
validation → event validation → FSM → semantic → on_violation callback —
correctly wires everything together and fires violations for non-compliant apps.

Uses minimal raw ASGI callables.  No framework required.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from asgion import AsgionConfig, inspect

if TYPE_CHECKING:
    from asgion.core._types import Message
    from asgion.core.violation import Violation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STRICT = AsgionConfig()  # min_severity=PERF — catches everything


def _http_scope(*, method: str = "GET", scheme: str = "http") -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }


async def _run(
    app: Any,
    *,
    config: AsgionConfig = _STRICT,
    method: str = "GET",
    scheme: str = "http",
    receives: list[Message] | None = None,
) -> list[Violation]:
    """Drive one HTTP request through inspect(app) and return all violations."""
    violations: list[Violation] = []
    wrapped = inspect(app, config=config, on_violation=violations.append)

    queue = list(
        receives
        if receives is not None
        else [{"type": "http.request", "body": b"", "more_body": False}]
    )
    queue.append({"type": "http.disconnect"})
    idx = 0

    async def receive() -> Message:
        nonlocal idx
        if idx < len(queue):
            msg = queue[idx]
            idx += 1
            return msg
        return {"type": "http.disconnect"}

    async def send(_message: Message) -> None:
        pass

    try:
        await wrapped(_http_scope(method=method, scheme=scheme), receive, send)
    except Exception:  # noqa: BLE001, S110
        pass  # misbehaving apps may raise; we care only about violations

    return violations


def _fires(violations: list[Violation], rule_id: str) -> None:
    found = {v.rule_id for v in violations}
    assert rule_id in found, f"Expected {rule_id!r} to fire. Got: {sorted(found) or 'none'}"


def _silent(violations: list[Violation], rule_id: str) -> None:
    found = {v.rule_id for v in violations}
    assert rule_id not in found, f"Expected {rule_id!r} to be silent. Got: {sorted(found)}"


# ---------------------------------------------------------------------------
# HTTP FSM — violations that fire during validate_send
# ---------------------------------------------------------------------------


async def test_hf002_body_before_start() -> None:
    """Body sent before response.start fires HF-002."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.body", "body": b"oops", "more_body": False})

    _fires(await _run(app), "HF-002")


async def test_hf003_duplicate_response_start() -> None:
    """Sending response.start twice fires HF-003."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    _fires(await _run(app), "HF-003")


async def test_hf004_body_after_complete() -> None:
    """Sending body after more_body=False fires HF-004."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        await send({"type": "http.response.body", "body": b"extra", "more_body": False})

    _fires(await _run(app), "HF-004")


async def test_hf005_send_after_disconnect() -> None:
    """Sending response after http.disconnect fires HF-005."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        msg = await receive()
        while msg.get("type") != "http.disconnect":
            msg = await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})

    _fires(await _run(app), "HF-005")


async def test_hf009_trailers_without_declaration() -> None:
    """Sending trailers without trailers=True in response.start fires HF-009."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        await send({"type": "http.response.trailers", "headers": [], "more_trailers": False})

    _fires(await _run(app), "HF-009")


async def test_hf012_204_with_real_body_bytes() -> None:
    """204 response with actual bytes fires HF-012."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send(
            {"type": "http.response.body", "body": b"should not be here", "more_body": False}
        )

    _fires(await _run(app), "HF-012")


async def test_hf012_204_empty_body_clean() -> None:
    """204 with body=b'' (ASGI protocol terminator) must NOT fire HF-012."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    _silent(await _run(app), "HF-012")


# ---------------------------------------------------------------------------
# HTTP FSM — violations that fire during validate_complete
# ---------------------------------------------------------------------------


async def test_hf001_no_response_sent() -> None:
    """App exits without sending response.start fires HF-001."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()

    _fires(await _run(app), "HF-001")


async def test_hf006_incomplete_response() -> None:
    """App exits after response.start but before body fires HF-006."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})

    _fires(await _run(app), "HF-006")


async def test_hf008_trailers_promised_not_sent() -> None:
    """trailers=True in response.start but no trailers event fires HF-008."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": [], "trailers": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    _fires(await _run(app), "HF-008")


async def test_hf007_request_after_body_complete() -> None:
    """App receives http.request after request body was already complete fires HF-007."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()  # http.request, more_body=False → body complete
        await receive()  # http.request again → HF-007
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    violations = await _run(
        app,
        receives=[
            {"type": "http.request", "body": b"", "more_body": False},
            {"type": "http.request", "body": b"extra", "more_body": False},
        ],
    )
    _fires(violations, "HF-007")


# ---------------------------------------------------------------------------
# Semantic violations — SEM rules
# ---------------------------------------------------------------------------


async def test_sem001_duplicate_content_type() -> None:
    """Two Content-Type headers in response fires SEM-001."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"content-type", b"application/json"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"hello", "more_body": False})

    _fires(await _run(app), "SEM-001")


async def test_sem002_missing_content_type_on_200() -> None:
    """200 response without Content-Type fires SEM-002 (INFO — needs strict config)."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", b"5")],
            }
        )
        await send({"type": "http.response.body", "body": b"hello", "more_body": False})

    _fires(await _run(app, config=_STRICT), "SEM-002")


async def test_sem003_content_length_mismatch() -> None:
    """Content-Length shorter than actual body fires SEM-003."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"content-length", b"3"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"12345", "more_body": False})

    _fires(await _run(app), "SEM-003")


async def test_sem004_insecure_cookie_on_http() -> None:
    """Set-Cookie without Secure flag on http:// scheme fires SEM-004."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"set-cookie", b"session=abc; HttpOnly"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    _fires(await _run(app, scheme="http"), "SEM-004")


async def test_sem004_silent_on_https() -> None:
    """Set-Cookie without Secure flag on https:// must NOT fire SEM-004."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"set-cookie", b"session=abc; HttpOnly"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    _silent(await _run(app, scheme="https"), "SEM-004")


# ---------------------------------------------------------------------------
# Full pipeline sanity — compliant app must produce no violations
# ---------------------------------------------------------------------------


async def test_clean_app_no_violations() -> None:
    """A well-behaved app must produce zero violations even with strict config."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", b"2"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    violations = await _run(app)
    assert violations == [], [(v.rule_id, v.message) for v in violations]
