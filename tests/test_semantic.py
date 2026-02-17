import time

import pytest

from asgion.core.config import AsgionConfig
from asgion.core.context import ConnectionContext
from asgion.validators.semantic import SemanticValidator
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx


@pytest.fixture
def validator() -> SemanticValidator:
    return SemanticValidator()


# --- SEM-001: Duplicate Content-Type header ---


def test_sem001_duplicate_content_type(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/html"),
                (b"content-type", b"application/json"),
            ],
        },
    )
    assert_violation(ctx, "SEM-001")


def test_sem001_single_content_type_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/html"),
            ],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "SEM-001"]
    assert matching == []


# --- SEM-002: Missing Content-Type on 2xx ---


def test_sem002_no_content_type_on_200(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [],
        },
    )
    assert_violation(ctx, "SEM-002")


def test_sem002_no_content_type_on_204_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 204,
            "headers": [],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "SEM-002"]
    assert matching == []


def test_sem002_no_content_type_on_304_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 304,
            "headers": [],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "SEM-002"]
    assert matching == []


def test_sem002_no_content_type_on_1xx_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 100,
            "headers": [],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "SEM-002"]
    assert matching == []


def test_sem002_no_content_type_on_404_ok(validator: SemanticValidator) -> None:
    """No SEM-002 for non-2xx responses."""
    ctx = make_http_ctx()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 404,
            "headers": [],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "SEM-002"]
    assert matching == []


# --- SEM-003: Content-Length mismatch ---


def test_sem003_content_length_mismatch(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain"), (b"content-length", b"10")],
        },
    )
    # Simulate body sent with wrong size
    ctx.http.total_body_bytes = 5
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-003")


def test_sem003_content_length_matches(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain"), (b"content-length", b"5")],
        },
    )
    ctx.http.total_body_bytes = 5
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-003"]
    assert matching == []


def test_sem003_no_content_length_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        },
    )
    ctx.http.total_body_bytes = 100
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-003"]
    assert matching == []


def test_sem003_skipped_on_disconnect(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain"), (b"content-length", b"10")],
        },
    )
    ctx.http.total_body_bytes = 3
    ctx.http.disconnected = True
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-003"]
    assert matching == []


# --- SEM-004: Set-Cookie without Secure on http:// ---


def _make_http_ctx_plain() -> ConnectionContext:
    """HTTP context with scheme=http (not https)."""
    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/test",
        "raw_path": b"/test",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }
    return ConnectionContext(scope)


def test_sem004_set_cookie_no_secure_on_http(validator: SemanticValidator) -> None:
    ctx = _make_http_ctx_plain()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/html"),
                (b"set-cookie", b"session=abc; HttpOnly; Path=/"),
            ],
        },
    )
    assert_violation(ctx, "SEM-004")


def test_sem004_set_cookie_with_secure_on_http_ok(
    validator: SemanticValidator,
) -> None:
    ctx = _make_http_ctx_plain()
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/html"),
                (b"set-cookie", b"session=abc; Secure; HttpOnly; Path=/"),
            ],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "SEM-004"]
    assert matching == []


def test_sem004_set_cookie_on_https_ok(validator: SemanticValidator) -> None:
    """No SEM-004 on https:// even without Secure flag."""
    ctx = make_http_ctx()  # scheme=https by default
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/html"),
                (b"set-cookie", b"session=abc; HttpOnly; Path=/"),
            ],
        },
    )
    matching = [v for v in ctx.violations if v.rule_id == "SEM-004"]
    assert matching == []


# --- SEM-005: App completed without http.disconnect ---


def test_sem005_no_disconnect_with_response(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.response_start_count = 1
    ctx.http.body_complete = False
    ctx.http.disconnected = False
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-005")


def test_sem005_disconnect_received_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.response_start_count = 1
    ctx.http.body_complete = False
    ctx.http.disconnected = True
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-005"]
    assert matching == []


def test_sem005_body_complete_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.response_start_count = 1
    ctx.http.body_complete = True
    ctx.http.disconnected = False
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-005"]
    assert matching == []


def test_sem005_no_response_start_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.response_start_count = 0
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-005"]
    assert matching == []


# --- Non-HTTP scope skipped ---


def test_validate_send_non_http_skipped(validator: SemanticValidator) -> None:
    from tests.conftest import make_ws_ctx

    ctx = make_ws_ctx()
    validator.validate_send(ctx, {"type": "http.response.start", "status": 200, "headers": []})
    assert_no_violations(ctx)


def test_validate_complete_non_http_skipped(validator: SemanticValidator) -> None:
    from tests.conftest import make_ws_ctx

    ctx = make_ws_ctx()
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


# --- SEM-006: Slow TTFB ---


def test_sem006_slow_ttfb(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    now = time.monotonic()
    ctx.http.request_received_at = now - 10.0
    ctx.http.response_started_at = now
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-006")


def test_sem006_fast_ttfb_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    now = time.monotonic()
    ctx.http.request_received_at = now - 0.1
    ctx.http.response_started_at = now
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-006"]
    assert matching == []


def test_sem006_no_timestamps_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-006"]
    assert matching == []


# --- SEM-007: Slow lifecycle ---


def test_sem007_slow_lifecycle(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    # Push start_time far into the past
    ctx.start_time = time.monotonic() - 60.0
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-007")


def test_sem007_fast_lifecycle_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-007"]
    assert matching == []


# --- SEM-008: Large response body ---


def test_sem008_large_body(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.total_body_bytes = 20 * 1024 * 1024  # 20 MB
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-008")


def test_sem008_small_body_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.total_body_bytes = 1024
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-008"]
    assert matching == []


# --- SEM-009: Response body not streamed ---


def test_sem009_single_large_chunk(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.body_chunks_sent = 1
    ctx.http.total_body_bytes = 2 * 1024 * 1024  # 2 MB in one chunk
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-009")


def test_sem009_multiple_chunks_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.body_chunks_sent = 5
    ctx.http.total_body_bytes = 2 * 1024 * 1024
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-009"]
    assert matching == []


def test_sem009_single_small_chunk_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.body_chunks_sent = 1
    ctx.http.total_body_bytes = 512
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-009"]
    assert matching == []


# --- SEM-010: Slow body delivery ---


def test_sem010_slow_body_delivery(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.response_started_at = time.monotonic() - 15.0
    ctx.http.body_complete = True
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-010")


def test_sem010_fast_body_delivery_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.response_started_at = time.monotonic() - 0.5
    ctx.http.body_complete = True
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-010"]
    assert matching == []


def test_sem010_body_not_complete_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.response_started_at = time.monotonic() - 15.0
    ctx.http.body_complete = False
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-010"]
    assert matching == []


# --- SEM-011: Excessive chunk fragmentation ---


def test_sem011_many_chunks(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.body_chunks_sent = 150
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-011")


def test_sem011_few_chunks_ok(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.body_chunks_sent = 10
    validator.validate_complete(ctx)
    matching = [v for v in ctx.violations if v.rule_id == "SEM-011"]
    assert matching == []


# --- validate_receive tracks request_received_at ---


def test_validate_receive_sets_request_timestamp(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    assert ctx.http.request_received_at is None
    validator.validate_receive(ctx, {"type": "http.request"})
    assert ctx.http.request_received_at is not None


def test_validate_receive_only_first(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    validator.validate_receive(ctx, {"type": "http.request"})
    first = ctx.http.request_received_at
    validator.validate_receive(ctx, {"type": "http.request"})
    assert ctx.http.request_received_at == first


# --- validate_send tracks response_started_at ---


def test_validate_send_sets_response_timestamp(validator: SemanticValidator) -> None:
    ctx = make_http_ctx()
    assert ctx.http is not None
    assert ctx.http.response_started_at is None
    validator.validate_send(
        ctx,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        },
    )
    assert ctx.http.response_started_at is not None


# --- Thresholds are configurable via AsgionConfig ---


def test_threshold_override_via_config() -> None:
    cfg = AsgionConfig(body_size_threshold=100)
    validator = SemanticValidator(config=cfg)
    ctx = make_http_ctx()
    assert ctx.http is not None
    ctx.http.total_body_bytes = 500
    validator.validate_complete(ctx)
    assert_violation(ctx, "SEM-008")
