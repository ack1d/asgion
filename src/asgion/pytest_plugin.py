"""pytest plugin for asgion — ASGI protocol validation in tests.

Provides the ``asgi_inspect`` fixture, ``@pytest.mark.asgi_validate`` marker,
and ``--asgi-strict`` CLI flag.

Usage::

    async def test_my_app(asgi_inspect):
        app = asgi_inspect(my_asgi_app)
        # ... drive the app via httpx, starlette TestClient, etc.
        assert app.violations == []

    @pytest.mark.asgi_validate(exclude_rules={"SEM-002"}, min_severity="warning")
    async def test_strict(asgi_inspect):
        app = asgi_inspect(my_asgi_app)
        # Violations auto-checked at teardown; test fails if any found.

CLI flag (applies asgi_validate to all tests using asgi_inspect)::

    pytest --asgi-strict
    pytest --asgi-strict --asgi-min-severity warning

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from asgion.core._types import ASGIApp, Receive, Scope, Send

_SEVERITY_ORDER: dict[str, int] = {
    "perf": 0,
    "info": 1,
    "warning": 2,
    "error": 3,
}

_APPS_KEY: pytest.StashKey[list[InspectedApp]] = pytest.StashKey()


@dataclass
class InspectedApp:
    """Wrapper returned by the ``asgi_inspect`` fixture.

    Collects violations during test execution.  Access ``violations``
    after driving the app to inspect protocol correctness.
    """

    _app: ASGIApp
    violations: list[Any] = field(default_factory=list)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._app(scope, receive, send)


def _make_inspected_app(
    app: ASGIApp,
    *,
    exclude_rules: set[str] | None = None,
) -> InspectedApp:
    from asgion.core.wrapper import inspect

    collected: list[Any] = []
    wrapped = inspect(
        app,
        on_violation=collected.append,
        exclude_rules=exclude_rules,
    )
    return InspectedApp(_app=wrapped, violations=collected)


def _format_violation(v: Any) -> str:
    location = ""
    if v.method and v.path:
        location = f" ({v.method} {v.path})"
    elif v.path:
        location = f" ({v.path})"
    line = f"  [{v.rule_id}] {v.severity}{location}: {v.message}"
    if v.hint:
        line += f"\n    hint: {v.hint}"
    return line


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("asgion", "ASGI protocol validation")
    group.addoption(
        "--asgi-strict",
        action="store_true",
        default=False,
        help="Auto-validate ASGI protocol on all tests using asgi_inspect fixture.",
    )
    group.addoption(
        "--asgi-min-severity",
        default="error",
        choices=list(_SEVERITY_ORDER),
        help="Minimum severity for --asgi-strict (default: error).",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "asgi_validate: mark test to auto-check ASGI violations at teardown. "
        "Options: exclude_rules=set(), min_severity='error'",
    )


@pytest.fixture
def asgi_inspect(request: pytest.FixtureRequest) -> Any:
    """Fixture that wraps ASGI apps with asgion validation.

    Returns a callable: ``asgi_inspect(app, exclude_rules=...)``
    that returns an ``InspectedApp`` with a ``.violations`` list.

    If the test is marked with ``@pytest.mark.asgi_validate`` or
    ``--asgi-strict`` is passed, violations are auto-checked at teardown.
    """
    apps: list[InspectedApp] = []
    # Stash before return — hook reads apps during "call" phase, not teardown
    request.node.stash[_APPS_KEY] = apps

    def factory(
        app: ASGIApp,
        *,
        exclude_rules: set[str] | None = None,
    ) -> InspectedApp:
        inspected = _make_inspected_app(app, exclude_rules=exclude_rules)
        apps.append(inspected)
        return inspected

    return factory


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Any:
    outcome = yield
    if call.when != "call":
        return
    report = outcome.get_result()
    if not report.passed:
        return

    apps = item.stash.get(_APPS_KEY, None)
    if apps is None:
        return

    marker = item.get_closest_marker("asgi_validate")
    global_strict = item.config.getoption("--asgi-strict", default=False)

    if marker is None and not global_strict:
        return

    marker_kwargs = (marker.kwargs if marker and marker.kwargs else {}) or {}
    marker_exclude: set[str] = marker_kwargs.get("exclude_rules", set())

    if marker is not None:
        min_severity = marker_kwargs.get("min_severity", "error")
    elif global_strict:
        min_severity = item.config.getoption("--asgi-min-severity", default="error")
    else:
        min_severity = "error"

    min_level = _SEVERITY_ORDER.get(min_severity, 3)

    all_violations = [
        v
        for app in apps
        for v in app.violations
        if _SEVERITY_ORDER.get(v.severity, 0) >= min_level and v.rule_id not in marker_exclude
    ]

    if all_violations:
        lines = [f"ASGI violations detected ({len(all_violations)}):"]
        lines.extend(_format_violation(v) for v in all_violations)
        report.outcome = "failed"
        report.longrepr = "\n".join(lines)
