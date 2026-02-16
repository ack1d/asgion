from typing import Any

import pytest

from asgion.spec import ALL_SPECS
from asgion.validators.spec_events import SpecEventValidator
from tests.conftest import assert_no_violations, assert_violation, make_lifespan_ctx


@pytest.fixture
def validator() -> SpecEventValidator:
    return SpecEventValidator(ALL_SPECS["lifespan"])


def _valid_scope() -> dict[str, Any]:
    return {
        "type": "lifespan",
        "asgi": {"version": "3.0"},
    }


# --- LS-001: type ---


def test_ls001_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    scope = {**_valid_scope(), "type": "http"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "LS-001")


def test_ls001_correct_type(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id == "LS-001"]
    assert matching == []


# --- LS-002/003: asgi required + type ---


def test_ls002_missing_asgi(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_scope(ctx, {"type": "lifespan"})
    assert_violation(ctx, "LS-002")


def test_ls003_asgi_wrong_type(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    scope = {**_valid_scope(), "asgi": "3.0"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "LS-003")


def test_ls002_003_valid(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id in ("LS-002", "LS-003")]
    assert matching == []


# --- LS-004: state type ---


def test_ls004_state_bad_type(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    scope = {**_valid_scope(), "state": "bad"}
    validator.validate_scope(ctx, scope)
    assert_violation(ctx, "LS-004")


def test_ls004_state_dict_passes(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    scope = {**_valid_scope(), "state": {}}
    validator.validate_scope(ctx, scope)
    matching = [v for v in ctx.violations if v.rule_id == "LS-004"]
    assert matching == []


def test_ls004_state_absent_passes(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_scope(ctx, _valid_scope())
    matching = [v for v in ctx.violations if v.rule_id == "LS-004"]
    assert matching == []


# --- Full valid scope ---


def test_valid_scope_no_violations(validator: SpecEventValidator) -> None:
    ctx = make_lifespan_ctx()
    validator.validate_scope(ctx, _valid_scope())
    assert_no_violations(ctx)
