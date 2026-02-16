import pytest

from asgion.core._types import LifespanPhase
from asgion.core.context import ConnectionContext
from asgion.validators.lifespan_fsm import LifespanFSMValidator
from tests.conftest import assert_no_violations, assert_violation, make_lifespan_ctx


@pytest.fixture
def validator() -> LifespanFSMValidator:
    return LifespanFSMValidator()


def _drive_to_starting(validator: LifespanFSMValidator, ctx: ConnectionContext) -> None:
    validator.validate_receive(ctx, {"type": "lifespan.startup"})


def _drive_to_started(validator: LifespanFSMValidator, ctx: ConnectionContext) -> None:
    _drive_to_starting(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.complete"})


def _drive_to_shutting_down(validator: LifespanFSMValidator, ctx: ConnectionContext) -> None:
    _drive_to_started(validator, ctx)
    validator.validate_receive(ctx, {"type": "lifespan.shutdown"})


def _drive_to_done(validator: LifespanFSMValidator, ctx: ConnectionContext) -> None:
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})


def test_happy_path_complete_lifecycle(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_done(validator, ctx)
    assert_no_violations(ctx)
    assert ctx.lifespan.phase == LifespanPhase.DONE


def test_happy_path_startup_failed_lifecycle(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_starting(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    assert_no_violations(ctx)
    assert ctx.lifespan.phase == LifespanPhase.FAILED


def test_happy_path_shutdown_failed_lifecycle(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    assert_no_violations(ctx)
    assert ctx.lifespan.phase == LifespanPhase.DONE


def test_lf001_startup_in_starting_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_starting(validator, ctx)
    validator.validate_receive(ctx, {"type": "lifespan.startup"})
    assert_violation(ctx, "LF-001")


def test_lf001_startup_in_started_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    validator.validate_receive(ctx, {"type": "lifespan.startup"})
    assert_violation(ctx, "LF-001")


def test_lf001_startup_in_shutting_down_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_receive(ctx, {"type": "lifespan.startup"})
    assert_violation(ctx, "LF-001")


def test_lf001_startup_in_waiting_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    assert ctx.lifespan.phase == LifespanPhase.WAITING
    validator.validate_receive(ctx, {"type": "lifespan.startup"})
    assert_no_violations(ctx)
    assert ctx.lifespan.phase == LifespanPhase.STARTING


def test_lf002_startup_complete_in_waiting_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    assert ctx.lifespan.phase == LifespanPhase.WAITING
    validator.validate_send(ctx, {"type": "lifespan.startup.complete"})
    assert_violation(ctx, "LF-002")


def test_lf002_startup_failed_in_waiting_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    assert ctx.lifespan.phase == LifespanPhase.WAITING
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    assert_violation(ctx, "LF-002")


def test_lf002_startup_complete_in_started_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    # Already completed; phase is STARTED. Second send is LF-003 (duplicate), not LF-002.
    validator.validate_send(ctx, {"type": "lifespan.startup.complete"})
    # This should be LF-003 not LF-002 because startup_completed flag is set
    assert_violation(ctx, "LF-003")


def test_lf002_startup_failed_in_shutting_down_state(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    # startup_completed is True, so LF-004 fires instead
    assert_violation(ctx, "LF-004")


def test_lf002_startup_complete_in_starting_passes(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_starting(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.complete"})
    assert_no_violations(ctx)


def test_lf003_duplicate_startup_complete(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    assert_no_violations(ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.complete"})
    assert_violation(ctx, "LF-003")


def test_lf003_single_startup_complete_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    matching = [v for v in ctx.violations if v.rule_id == "LF-003"]
    assert matching == []


def test_lf004_failed_after_complete(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    assert_violation(ctx, "LF-004")


def test_lf004_complete_after_failed(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_starting(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    assert_no_violations(ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.complete"})
    assert_violation(ctx, "LF-004")


def test_lf004_single_complete_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    matching = [v for v in ctx.violations if v.rule_id == "LF-004"]
    assert matching == []


def test_lf004_single_failed_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_starting(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    matching = [v for v in ctx.violations if v.rule_id == "LF-004"]
    assert matching == []


def test_lf005_shutdown_in_waiting_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_receive(ctx, {"type": "lifespan.shutdown"})
    assert_violation(ctx, "LF-005")


def test_lf005_shutdown_in_starting_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_starting(validator, ctx)
    validator.validate_receive(ctx, {"type": "lifespan.shutdown"})
    assert_violation(ctx, "LF-005")


def test_lf005_shutdown_in_failed_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_starting(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    assert ctx.lifespan.phase == LifespanPhase.FAILED
    validator.validate_receive(ctx, {"type": "lifespan.shutdown"})
    assert_violation(ctx, "LF-005")


def test_lf005_shutdown_after_started_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    validator.validate_receive(ctx, {"type": "lifespan.shutdown"})
    assert_no_violations(ctx)


def test_lf006_shutdown_complete_in_waiting_state(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert_violation(ctx, "LF-006")


def test_lf006_shutdown_complete_in_started_state(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert_violation(ctx, "LF-006")


def test_lf006_shutdown_failed_in_started_state(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    assert_violation(ctx, "LF-006")


def test_lf006_duplicate_shutdown_complete(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert_no_violations(ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert_violation(ctx, "LF-006")


def test_lf006_shutdown_complete_in_shutting_down_passes(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert_no_violations(ctx)


def test_lf006_shutdown_failed_in_shutting_down_passes(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    assert_no_violations(ctx)


def test_lf007_failed_after_complete(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert_no_violations(ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    assert_violation(ctx, "LF-007")


def test_lf007_complete_after_failed(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    assert_no_violations(ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert_violation(ctx, "LF-007")


def test_lf007_single_shutdown_complete_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_done(validator, ctx)
    matching = [v for v in ctx.violations if v.rule_id == "LF-007"]
    assert matching == []


def test_lf007_single_shutdown_failed_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    matching = [v for v in ctx.violations if v.rule_id == "LF-007"]
    assert matching == []


def test_lf008_exit_during_shutdown_without_response(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    assert ctx.lifespan.phase == LifespanPhase.SHUTTING_DOWN
    validator.validate_complete(ctx)
    v = assert_violation(ctx, "LF-008")
    assert v.severity == "info"


def test_lf008_exit_after_shutdown_complete_passes(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_done(validator, ctx)
    assert ctx.lifespan.phase == LifespanPhase.DONE
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_lf008_exit_after_shutdown_failed_passes(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_shutting_down(validator, ctx)
    validator.validate_send(ctx, {"type": "lifespan.shutdown.failed"})
    assert ctx.lifespan.phase == LifespanPhase.DONE
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_lf008_exit_in_waiting_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    assert ctx.lifespan.phase == LifespanPhase.WAITING
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_lf008_exit_in_started_passes(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    _drive_to_started(validator, ctx)
    assert ctx.lifespan.phase == LifespanPhase.STARTED
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_lf008_non_lifespan_scope_ignored(validator: LifespanFSMValidator) -> None:
    from tests.conftest import make_http_ctx

    ctx = make_http_ctx()
    validator.validate_complete(ctx)
    assert_no_violations(ctx)


def test_phase_transitions_happy_path(validator: LifespanFSMValidator) -> None:
    ctx = make_lifespan_ctx()
    assert ctx.lifespan.phase == LifespanPhase.WAITING

    validator.validate_receive(ctx, {"type": "lifespan.startup"})
    assert ctx.lifespan.phase == LifespanPhase.STARTING

    validator.validate_send(ctx, {"type": "lifespan.startup.complete"})
    assert ctx.lifespan.phase == LifespanPhase.STARTED

    validator.validate_receive(ctx, {"type": "lifespan.shutdown"})
    assert ctx.lifespan.phase == LifespanPhase.SHUTTING_DOWN

    validator.validate_send(ctx, {"type": "lifespan.shutdown.complete"})
    assert ctx.lifespan.phase == LifespanPhase.DONE

    assert_no_violations(ctx)


def test_phase_transitions_startup_failure_path(
    validator: LifespanFSMValidator,
) -> None:
    ctx = make_lifespan_ctx()
    assert ctx.lifespan.phase == LifespanPhase.WAITING

    validator.validate_receive(ctx, {"type": "lifespan.startup"})
    assert ctx.lifespan.phase == LifespanPhase.STARTING

    validator.validate_send(ctx, {"type": "lifespan.startup.failed"})
    assert ctx.lifespan.phase == LifespanPhase.FAILED

    assert_no_violations(ctx)
