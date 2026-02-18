"""Tests for the asgion pytest plugin."""

from __future__ import annotations

import pytest

from asgion.pytest_plugin import InspectedApp, _format_violation, _make_inspected_app

pytest_plugins = ["pytester"]


async def _good_app(scope: dict, receive: object, send: object) -> None:  # type: ignore[type-arg]
    recv = receive  # type: ignore[operator]
    snd = send  # type: ignore[operator]
    await recv()
    await snd(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        }
    )
    await snd({"type": "http.response.body", "body": b"OK", "more_body": False})


async def _bad_app(scope: dict, receive: object, send: object) -> None:  # type: ignore[type-arg]
    recv = receive  # type: ignore[operator]
    snd = send  # type: ignore[operator]
    await recv()
    await snd(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    # Send body with string instead of bytes — triggers HE-012
    await snd({"type": "http.response.body", "body": "not bytes"})


def _make_http_scope() -> dict:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/test",
        "raw_path": b"/test",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }


async def _drive(app: InspectedApp) -> None:
    """Drive an inspected app through a minimal HTTP request."""
    scope = _make_http_scope()
    events = iter([{"type": "http.request", "body": b"", "more_body": False}])

    async def receive() -> dict:
        return next(events)

    async def send(msg: dict) -> None:
        pass

    await app(scope, receive, send)  # type: ignore[arg-type]


# --- _make_inspected_app ---


async def test_inspected_app_collects_no_violations() -> None:
    inspected = _make_inspected_app(_good_app)
    scope = _make_http_scope()

    events = iter(
        [
            {"type": "http.request", "body": b"", "more_body": False},
        ]
    )

    sent: list[dict] = []

    async def receive() -> dict:
        return next(events)

    async def send(msg: dict) -> None:
        sent.append(msg)

    await inspected(scope, receive, send)  # type: ignore[arg-type]
    assert inspected.violations == []
    assert len(sent) == 2


async def test_inspected_app_collects_violations() -> None:
    inspected = _make_inspected_app(_bad_app)
    await _drive(inspected)
    assert len(inspected.violations) > 0
    rule_ids = {v.rule_id for v in inspected.violations}
    assert "HE-012" in rule_ids


async def test_inspected_app_exclude_rules() -> None:
    inspected = _make_inspected_app(_bad_app, exclude_rules={"HE-012"})
    await _drive(inspected)
    rule_ids = {v.rule_id for v in inspected.violations}
    assert "HE-012" not in rule_ids


def test_inspected_app_is_callable() -> None:
    inspected = _make_inspected_app(_good_app)
    assert isinstance(inspected, InspectedApp)
    assert callable(inspected)


# --- _format_violation ---


def test_format_violation_with_method_and_path() -> None:
    from asgion.core.violation import Violation

    v = Violation(
        rule_id="HE-012",
        severity="error",
        message="body must be bytes",
        hint="Use bytes, not str",
        scope_type="http",
        path="/test",
        method="GET",
    )
    formatted = _format_violation(v)
    assert "(GET /test)" in formatted
    assert "[HE-012]" in formatted
    assert "hint: Use bytes, not str" in formatted


def test_format_violation_without_method() -> None:
    from asgion.core.violation import Violation

    v = Violation(
        rule_id="LF-001",
        severity="error",
        message="bad lifespan",
        path="/lifespan",
    )
    formatted = _format_violation(v)
    assert "(/lifespan)" in formatted
    assert "LF-001" in formatted


def test_format_violation_no_location() -> None:
    from asgion.core.violation import Violation

    v = Violation(
        rule_id="G-001",
        severity="error",
        message="scope must be dict",
    )
    formatted = _format_violation(v)
    assert "(" not in formatted
    assert "[G-001]" in formatted


# --- asgi_inspect fixture ---


async def test_asgi_inspect_fixture(asgi_inspect: object) -> None:
    factory = asgi_inspect  # type: ignore[operator]
    app = factory(_good_app)

    scope = _make_http_scope()
    events = iter([{"type": "http.request", "body": b"", "more_body": False}])

    sent: list[dict] = []

    async def receive() -> dict:
        return next(events)

    async def send(msg: dict) -> None:
        sent.append(msg)

    await app(scope, receive, send)  # type: ignore[arg-type]
    assert app.violations == []


async def test_asgi_inspect_detects_violations(asgi_inspect: object) -> None:
    factory = asgi_inspect  # type: ignore[operator]
    app = factory(_bad_app)
    await _drive(app)
    assert len(app.violations) > 0


# --- Marker: asgi_validate ---


@pytest.mark.asgi_validate(min_severity="error")
async def test_marker_passes_on_good_app(asgi_inspect: object) -> None:
    factory = asgi_inspect  # type: ignore[operator]
    app = factory(_good_app)
    await _drive(app)
    # No assertion — the marker teardown should pass (no error-level violations)


@pytest.mark.asgi_validate(exclude_rules={"HE-012"}, min_severity="error")
async def test_marker_exclude_rules(asgi_inspect: object) -> None:
    factory = asgi_inspect  # type: ignore[operator]
    app = factory(_bad_app)
    await _drive(app)
    # HE-012 excluded on marker — teardown should pass


# --- --asgi-strict flag (tested via pytester-like pattern) ---


def test_asgi_strict_option_registered(pytestconfig: pytest.Config) -> None:
    # Verify the option exists (won't raise)
    pytestconfig.getoption("--asgi-strict")


def test_asgi_min_severity_option_registered(pytestconfig: pytest.Config) -> None:
    pytestconfig.getoption("--asgi-min-severity")


# --- pytester integration tests (subprocess) ---

# Shared test app code injected into pytester test files
_APP_CODE = """
import pytest

async def _good_app(scope, receive, send):
    await receive()
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"text/plain; charset=utf-8")],
    })
    await send({"type": "http.response.body", "body": b"OK", "more_body": False})

async def _bad_app(scope, receive, send):
    await receive()
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"text/plain")],
    })
    await send({"type": "http.response.body", "body": "not bytes"})

def _make_scope():
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/api/users",
        "raw_path": b"/api/users",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }

async def _drive(app):
    scope = _make_scope()
    events = iter([{"type": "http.request", "body": b"", "more_body": False}])
    async def receive():
        return next(events)
    async def send(msg):
        pass
    await app(scope, receive, send)
"""


def test_pytester_marker_fails_on_bad_app(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(f"""
{_APP_CODE}

@pytest.mark.asgi_validate(min_severity="error")
async def test_bad(asgi_inspect):
    app = asgi_inspect(_bad_app)
    await _drive(app)
""")
    pytester.makeini("[pytest]\nasyncio_mode = auto\n")
    result = pytester.runpytest_subprocess()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*ASGI violations detected*"])
    result.stdout.fnmatch_lines(["*HE-012*"])
    result.stdout.fnmatch_lines(["*POST /api/users*"])


def test_pytester_marker_passes_on_good_app(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(f"""
{_APP_CODE}

@pytest.mark.asgi_validate(min_severity="error")
async def test_good(asgi_inspect):
    app = asgi_inspect(_good_app)
    await _drive(app)
""")
    pytester.makeini("[pytest]\nasyncio_mode = auto\n")
    result = pytester.runpytest_subprocess()
    result.assert_outcomes(passed=1)


def test_pytester_marker_exclude_rules(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(f"""
{_APP_CODE}

@pytest.mark.asgi_validate(exclude_rules={{"HE-012"}}, min_severity="error")
async def test_excluded(asgi_inspect):
    app = asgi_inspect(_bad_app)
    await _drive(app)
""")
    pytester.makeini("[pytest]\nasyncio_mode = auto\n")
    result = pytester.runpytest_subprocess()
    # HE-012 excluded, remaining violations may be below error threshold
    result.assert_outcomes(passed=1)


def test_pytester_asgi_strict_flag(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(f"""
{_APP_CODE}

async def test_no_marker(asgi_inspect):
    app = asgi_inspect(_bad_app)
    await _drive(app)
""")
    pytester.makeini("[pytest]\nasyncio_mode = auto\n")
    # Without --asgi-strict: passes (no marker, no auto-check)
    result = pytester.runpytest_subprocess()
    result.assert_outcomes(passed=1)
    # With --asgi-strict: fails
    result = pytester.runpytest_subprocess("--asgi-strict")
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*ASGI violations detected*"])


def test_pytester_asgi_strict_min_severity(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(f"""
{_APP_CODE}

async def test_with_strict(asgi_inspect):
    app = asgi_inspect(_bad_app)
    await _drive(app)
""")
    pytester.makeini("[pytest]\nasyncio_mode = auto\n")
    # --asgi-strict with min_severity=warning should also catch warnings
    result = pytester.runpytest_subprocess("--asgi-strict", "--asgi-min-severity", "warning")
    result.assert_outcomes(failed=1)
