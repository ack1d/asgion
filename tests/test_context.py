import time
from typing import TYPE_CHECKING

from asgion.core._types import HTTPPhase, LifespanPhase, Severity, WSPhase
from asgion.core.context import ConnectionContext
from asgion.core.rule import Rule
from tests.conftest import make_http_ctx, make_lifespan_ctx, make_ws_ctx

if TYPE_CHECKING:
    from asgion.core.violation import Violation

_RULE = Rule("CTX-001", Severity.ERROR, "test rule", layer="test", scope_types=("http",))


class TestConnectionContextInit:
    def test_http_scope_creates_http_state(self) -> None:
        ctx = make_http_ctx()
        assert ctx.scope_type == "http"
        assert ctx.http is not None
        assert ctx.http.phase == HTTPPhase.WAITING
        assert ctx.ws is None
        assert ctx.lifespan is None

    def test_ws_scope_creates_ws_state(self) -> None:
        ctx = make_ws_ctx()
        assert ctx.scope_type == "websocket"
        assert ctx.ws is not None
        assert ctx.ws.phase == WSPhase.CONNECTING
        assert ctx.http is None
        assert ctx.lifespan is None

    def test_lifespan_scope_creates_lifespan_state(self) -> None:
        ctx = make_lifespan_ctx()
        assert ctx.scope_type == "lifespan"
        assert ctx.lifespan is not None
        assert ctx.lifespan.phase == LifespanPhase.WAITING
        assert ctx.http is None
        assert ctx.ws is None

    def test_unknown_scope_type(self) -> None:
        ctx = ConnectionContext({"type": "ftp", "asgi": {"version": "3.0"}})
        assert ctx.scope_type == "ftp"
        assert ctx.http is None
        assert ctx.ws is None
        assert ctx.lifespan is None

    def test_path_and_method_extracted(self) -> None:
        ctx = make_http_ctx(path="/api/v1", method="POST")
        assert ctx.path == "/api/v1"
        assert ctx.method == "POST"

    def test_missing_path_and_method(self) -> None:
        ctx = ConnectionContext({"type": "lifespan", "asgi": {"version": "3.0"}})
        assert ctx.path == ""
        assert ctx.method == ""


class TestViolation:
    def test_basic_violation(self) -> None:
        ctx = make_http_ctx()
        ctx.violation(_RULE)
        assert len(ctx.violations) == 1
        v = ctx.violations[0]
        assert v.rule_id == "CTX-001"
        assert v.severity == Severity.ERROR
        assert v.message == "test rule"

    def test_violation_with_detail(self) -> None:
        ctx = make_http_ctx()
        ctx.violation(_RULE, "custom detail")
        assert ctx.violations[0].message == "custom detail"

    def test_violation_with_hint_override(self) -> None:
        rule = Rule(
            "CTX-002",
            Severity.WARNING,
            "msg",
            hint="default hint",
            layer="test",
            scope_types=("http",),
        )
        ctx = make_http_ctx()
        ctx.violation(rule, hint="override hint")
        assert ctx.violations[0].hint == "override hint"

    def test_violation_uses_rule_hint(self) -> None:
        rule = Rule(
            "CTX-003",
            Severity.WARNING,
            "msg",
            hint="rule hint",
            layer="test",
            scope_types=("http",),
        )
        ctx = make_http_ctx()
        ctx.violation(rule)
        assert ctx.violations[0].hint == "rule hint"

    def test_violation_includes_scope_metadata(self) -> None:
        ctx = make_http_ctx(path="/api", method="DELETE")
        ctx.violation(_RULE)
        v = ctx.violations[0]
        assert v.scope_type == "http"
        assert v.path == "/api"
        assert v.method == "DELETE"

    def test_violation_timestamp(self) -> None:
        ctx = make_http_ctx()
        ctx.violation(_RULE)
        assert ctx.violations[0].timestamp >= 0

    def test_violation_extra_context(self) -> None:
        ctx = make_http_ctx()
        ctx.violation(_RULE, "msg", key="val")
        assert ctx.violations[0].context == {"key": "val"}

    def test_violation_no_extra_context(self) -> None:
        ctx = make_http_ctx()
        ctx.violation(_RULE)
        assert ctx.violations[0].context is None


class TestDisabledRules:
    def test_disabled_rule_not_recorded(self) -> None:
        ctx = make_http_ctx(disabled_rules=frozenset({"CTX-001"}))
        ctx.violation(_RULE)
        assert ctx.violations == []

    def test_non_disabled_rule_recorded(self) -> None:
        ctx = make_http_ctx(disabled_rules=frozenset({"OTHER-001"}))
        ctx.violation(_RULE)
        assert len(ctx.violations) == 1


class TestOnViolationCallback:
    def test_callback_fires(self) -> None:
        captured: list[Violation] = []
        ctx = ConnectionContext(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "method": "GET",
                "path": "/",
                "query_string": b"",
                "root_path": "",
                "headers": [],
                "http_version": "1.1",
            },
            _on_violation=captured.append,
        )
        ctx.violation(_RULE)
        assert len(captured) == 1
        assert captured[0].rule_id == "CTX-001"

    def test_callback_not_fired_for_disabled(self) -> None:
        captured: list[Violation] = []
        ctx = ConnectionContext(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "method": "GET",
                "path": "/",
                "query_string": b"",
                "root_path": "",
                "headers": [],
                "http_version": "1.1",
            },
            _on_violation=captured.append,
            _disabled_rules=frozenset({"CTX-001"}),
        )
        ctx.violation(_RULE)
        assert captured == []


class TestElapsed:
    def test_elapsed_is_positive(self) -> None:
        ctx = make_http_ctx()
        time.sleep(0.01)
        assert ctx.elapsed > 0

    def test_elapsed_increases(self) -> None:
        ctx = make_http_ctx()
        t1 = ctx.elapsed
        time.sleep(0.01)
        t2 = ctx.elapsed
        assert t2 > t1


class TestEvents:
    def test_events_initially_empty(self) -> None:
        ctx = make_http_ctx()
        assert ctx.events == []
