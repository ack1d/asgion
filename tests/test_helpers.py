import pytest

from asgion.core._types import Severity
from asgion.core.context import ConnectionContext
from asgion.core.rule import Rule
from asgion.validators._helpers import validate_headers
from tests.conftest import assert_no_violations, assert_violation, make_http_ctx

_RULE = Rule("TEST-H", Severity.ERROR, "header error", layer="test", scope_types=("http",))
_LC_RULE = Rule("TEST-LC", Severity.WARNING, "lowercase error", layer="test", scope_types=("http",))


@pytest.fixture
def ctx() -> ConnectionContext:
    return make_http_ctx()


class TestValidateHeadersStructure:
    def test_not_iterable(self, ctx: ConnectionContext) -> None:
        validate_headers(ctx, 42, _RULE)
        assert_violation(ctx, "TEST-H")

    def test_string_not_iterable(self, ctx: ConnectionContext) -> None:
        validate_headers(ctx, "bad", _RULE)
        assert_violation(ctx, "TEST-H")

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param([(b"only-one",)], id="single-element-tuple"),
            pytest.param([(b"a", b"b", b"c")], id="three-element-tuple"),
            pytest.param([b"not-a-pair"], id="bare-bytes"),
            pytest.param([42], id="bare-int"),
        ],
    )
    def test_bad_pair_format(self, ctx: ConnectionContext, headers: list) -> None:
        validate_headers(ctx, headers, _RULE)
        assert_violation(ctx, "TEST-H")

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param([("name", b"value")], id="str-name"),
            pytest.param([(123, b"value")], id="int-name"),
        ],
    )
    def test_name_not_bytes(self, ctx: ConnectionContext, headers: list) -> None:
        validate_headers(ctx, headers, _RULE)
        assert_violation(ctx, "TEST-H")

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param([(b"name", "value")], id="str-value"),
            pytest.param([(b"name", 123)], id="int-value"),
        ],
    )
    def test_value_not_bytes(self, ctx: ConnectionContext, headers: list) -> None:
        validate_headers(ctx, headers, _RULE)
        assert_violation(ctx, "TEST-H")


class TestValidateHeadersValid:
    def test_empty_list(self, ctx: ConnectionContext) -> None:
        validate_headers(ctx, [], _RULE)
        assert_no_violations(ctx)

    def test_valid_tuple_pairs(self, ctx: ConnectionContext) -> None:
        validate_headers(ctx, [(b"content-type", b"text/plain")], _RULE)
        assert_no_violations(ctx)

    def test_valid_list_pairs(self, ctx: ConnectionContext) -> None:
        validate_headers(ctx, [[b"content-type", b"text/plain"]], _RULE)
        assert_no_violations(ctx)

    def test_multiple_headers(self, ctx: ConnectionContext) -> None:
        validate_headers(
            ctx,
            [(b"content-type", b"text/plain"), (b"x-custom", b"value")],
            _RULE,
        )
        assert_no_violations(ctx)


class TestValidateHeadersLowercase:
    def test_uppercase_fires_lowercase_rule(self, ctx: ConnectionContext) -> None:
        validate_headers(
            ctx,
            [(b"Content-Type", b"text/plain")],
            _RULE,
            lowercase_rule=_LC_RULE,
        )
        assert_violation(ctx, "TEST-LC")

    def test_lowercase_passes(self, ctx: ConnectionContext) -> None:
        validate_headers(
            ctx,
            [(b"content-type", b"text/plain")],
            _RULE,
            lowercase_rule=_LC_RULE,
        )
        lc = [v for v in ctx.violations if v.rule_id == "TEST-LC"]
        assert lc == []

    def test_no_lowercase_rule_skips_check(self, ctx: ConnectionContext) -> None:
        validate_headers(
            ctx,
            [(b"Content-Type", b"text/plain")],
            _RULE,
        )
        assert_no_violations(ctx)
