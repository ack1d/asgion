import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_lifespan_ctx


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["lifespan"])


@pytest.mark.parametrize(
    "event_type",
    [
        pytest.param("lifespan.bogus", id="bogus"),
        pytest.param("lifespan.startup.complete", id="send_event"),
        pytest.param("", id="empty"),
        pytest.param("http.request", id="http_event"),
    ],
)
def test_le001_invalid_receive_type(validator: SpecEventValidator, event_type: str) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_receive(ctx, {"type": event_type})
    v = assert_violation(ctx, "LE-001")
    assert v.severity == "error"


@pytest.mark.parametrize(
    "event_type",
    [
        pytest.param("lifespan.startup", id="startup"),
        pytest.param("lifespan.shutdown", id="shutdown"),
    ],
)
def test_le001_valid_receive_no_violation(validator: SpecEventValidator, event_type: str) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_receive(ctx, {"type": event_type})
    assert_no_violations(ctx)


@pytest.mark.parametrize(
    "event_type",
    [
        pytest.param("lifespan.bogus", id="bogus"),
        pytest.param("lifespan.startup", id="receive_event"),
        pytest.param("", id="empty"),
        pytest.param("http.response.start", id="http_event"),
    ],
)
def test_le003_invalid_send_type(validator: SpecEventValidator, event_type: str) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": event_type})
    v = assert_violation(ctx, "LE-002")
    assert v.severity == "error"


@pytest.mark.parametrize(
    "event",
    [
        pytest.param({"type": "lifespan.startup.complete"}, id="startup_complete"),
        pytest.param({"type": "lifespan.startup.failed", "message": "boom"}, id="startup_failed"),
        pytest.param({"type": "lifespan.shutdown.complete"}, id="shutdown_complete"),
        pytest.param({"type": "lifespan.shutdown.failed", "message": "err"}, id="shutdown_failed"),
    ],
)
def test_le003_valid_send_no_violation(
    validator: SpecEventValidator, event: dict[str, object]
) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, event)
    assert_no_violations(ctx)


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(123, id="is_int"),
        pytest.param(b"err", id="is_bytes"),
        pytest.param(["err"], id="is_list"),
        pytest.param(None, id="is_none"),
    ],
)
def test_le004_startup_failed_message_invalid_type(
    validator: SpecEventValidator, message: object
) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": "lifespan.startup.failed", "message": message})
    v = assert_violation(ctx, "LE-003")
    assert v.severity == "error"


def test_le004_startup_failed_message_str_passes(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": "lifespan.startup.failed", "message": "startup error"})
    matching = [v for v in ctx.violations if v.rule_id == "LE-003"]
    assert matching == []


def test_le004_startup_failed_message_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    matching = [v for v in ctx.violations if v.rule_id == "LE-003"]
    assert matching == []


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(42, id="is_int"),
        pytest.param(b"fail", id="is_bytes"),
        pytest.param(["fail"], id="is_list"),
        pytest.param(None, id="is_none"),
    ],
)
def test_le006_shutdown_failed_message_invalid_type(
    validator: SpecEventValidator, message: object
) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed", "message": message})
    v = assert_violation(ctx, "LE-004")
    assert v.severity == "error"


def test_le006_shutdown_failed_message_str_passes(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed", "message": "shutdown error"})
    matching = [v for v in ctx.violations if v.rule_id == "LE-004"]
    assert matching == []


def test_le006_shutdown_failed_message_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    matching = [v for v in ctx.violations if v.rule_id == "LE-004"]
    assert matching == []
