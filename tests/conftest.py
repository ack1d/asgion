from typing import TYPE_CHECKING

from asgion.core.context import ConnectionContext
from asgion.core.violation import Violation

if TYPE_CHECKING:
    from asgion.core._types import Scope


def make_http_ctx(
    *,
    path: str = "/test",
    method: str = "GET",
    disabled_rules: frozenset[str] | None = None,
) -> ConnectionContext:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }
    return ConnectionContext(scope, _disabled_rules=disabled_rules or frozenset())


def make_ws_ctx(*, path: str = "/ws") -> ConnectionContext:
    scope: Scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": path,
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "subprotocols": [],
    }
    return ConnectionContext(scope)


def make_lifespan_ctx() -> ConnectionContext:
    scope: Scope = {
        "type": "lifespan",
        "asgi": {"version": "3.0"},
    }
    return ConnectionContext(scope)


def assert_violation(ctx: ConnectionContext, rule_id: str) -> Violation:
    matching = [v for v in ctx.violations if v.rule_id == rule_id]
    assert matching, (
        f"Expected violation {rule_id}, got: {[v.rule_id for v in ctx.violations] or 'none'}"
    )
    return matching[0]


def assert_violations(ctx: ConnectionContext, *rule_ids: str) -> list[Violation]:
    found_ids = {v.rule_id for v in ctx.violations}
    expected = set(rule_ids)
    missing = expected - found_ids
    assert not missing, f"Missing violations: {missing}. Got: {found_ids}"
    return [v for v in ctx.violations if v.rule_id in expected]


def assert_no_violations(ctx: ConnectionContext) -> None:
    assert ctx.violations == [], (
        f"Expected no violations, got: {[(v.rule_id, v.message) for v in ctx.violations]}"
    )
