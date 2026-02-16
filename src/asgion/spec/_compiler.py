from typing import Any

from asgion.core._types import Message, Severity
from asgion.core.context import ConnectionContext
from asgion.core.rule import Rule
from asgion.spec._checks import (
    CheckSpec,
    ExactlyOneNonNull,
    FieldRequired,
    FieldType,
    FieldValue,
    HeadersFormat,
)
from asgion.spec._protocol import CheckFn, CompiledSpec, ProtocolSpec
from asgion.validators._helpers import validate_headers


def compile_spec(spec: ProtocolSpec) -> CompiledSpec:
    """Compile a ProtocolSpec into rules + dispatch tables."""
    rules: dict[str, Rule] = {}
    receive_dispatch: dict[str, list[CheckFn]] = {}
    send_dispatch: dict[str, list[CheckFn]] = {}

    for event in spec.events:
        fns: list[CheckFn] = []
        for check in event.checks:
            fn = _compile_check(check, event.event_type, spec.layer, spec.name, rules)
            fns.append(fn)

        if event.direction == "receive":
            receive_dispatch[event.event_type] = fns
        else:
            send_dispatch[event.event_type] = fns

    # Invalid type rules (auto-generate hint from valid types if not provided)
    receive_types = frozenset(receive_dispatch)
    send_types = frozenset(send_dispatch)

    invalid_receive_rule = _make_invalid_rule(
        spec.invalid_receive_rule_id,
        spec.invalid_receive_summary,
        spec.invalid_receive_hint,
        receive_types,
        spec.layer,
        spec.name,
        rules,
    )
    invalid_send_rule = _make_invalid_rule(
        spec.invalid_send_rule_id,
        spec.invalid_send_summary,
        spec.invalid_send_hint,
        send_types,
        spec.layer,
        spec.name,
        rules,
    )

    # Scope checks
    scope_layer = spec.scope_layer or spec.layer
    scope_fns: list[CheckFn] = []
    for check in spec.scope_checks:
        fn = _compile_check(check, "scope", scope_layer, spec.name, rules)
        scope_fns.append(fn)

    return CompiledSpec(
        rules=rules,
        receive_dispatch={k: tuple(v) for k, v in receive_dispatch.items()},
        send_dispatch={k: tuple(v) for k, v in send_dispatch.items()},
        valid_receive_types=receive_types,
        valid_send_types=send_types,
        invalid_receive_rule=invalid_receive_rule,
        invalid_send_rule=invalid_send_rule,
        scope_fns=tuple(scope_fns),
    )


def _make_invalid_rule(
    rule_id: str,
    summary: str,
    hint: str,
    valid_types: frozenset[str],
    layer: str,
    protocol: str,
    rules: dict[str, Rule],
) -> Rule | None:
    if not rule_id:
        return None
    if not hint and valid_types:
        hint = f"Expected one of: {', '.join(sorted(valid_types))}"
    rule = Rule(
        id=rule_id,
        severity=Severity.ERROR,
        summary=summary,
        hint=hint,
        layer=layer,
        scope_types=(protocol,),
    )
    rules[rule_id] = rule
    return rule


def _compile_check(
    check: CheckSpec,
    event_type: str,
    layer: str,
    protocol: str,
    rules: dict[str, Rule],
) -> CheckFn:
    scope_types = (protocol,)

    match check:
        case FieldRequired(field=field, rule_id=rid, severity=sev, summary=summary, hint=hint):
            summary = summary or f"{event_type} missing '{field}' field"
            rule = Rule(rid, sev, summary, hint=hint, layer=layer, scope_types=scope_types)
            rules[rid] = rule

            def fn_required(ctx: ConnectionContext, msg: Message) -> None:
                if field not in msg:
                    ctx.violation(rule)

            return fn_required

        case FieldType(
            field=field,
            expected=expected,
            rule_id=rid,
            nullable=nullable,
            severity=sev,
            summary=summary,
            hint=hint,
        ):
            return _compile_field_type(
                field,
                expected,
                rid,
                nullable,
                sev,
                summary,
                hint,
                event_type,
                layer,
                scope_types,
                rules,
            )

        case FieldValue(
            field=field,
            check=check_fn,
            rule_id=rid,
            severity=sev,
            summary=summary,
            hint=hint,
        ):
            summary = summary or f"Invalid {event_type}['{field}'] value"
            rule = Rule(rid, sev, summary, hint=hint, layer=layer, scope_types=scope_types)
            rules[rid] = rule

            def fn_value(ctx: ConnectionContext, msg: Message) -> None:
                if field in msg:
                    result = check_fn(msg[field])
                    if result is not None:
                        ctx.violation(rule, result)

            return fn_value

        case ExactlyOneNonNull(
            field_a=field_a,
            field_b=field_b,
            rule_id=rid,
            severity=sev,
            summary=summary,
            hint=hint,
        ):
            summary = (
                summary
                or f"{event_type} must have exactly one of '{field_a}' or '{field_b}' as non-None"
            )
            rule = Rule(rid, sev, summary, hint=hint, layer=layer, scope_types=scope_types)
            rules[rid] = rule

            def fn_one_of(ctx: ConnectionContext, msg: Message) -> None:
                val_a = msg.get(field_a)
                val_b = msg.get(field_b)
                has_a = val_a is not None
                has_b = val_b is not None
                if has_a == has_b:
                    ctx.violation(rule)

            return fn_one_of

        case HeadersFormat():
            return _compile_headers_format(check, event_type, layer, scope_types, rules)


def _compile_field_type(
    field: str,
    expected: type | tuple[type, ...],
    rid: str,
    nullable: bool,
    sev: Severity,
    summary: str,
    hint: str,
    event_type: str,
    layer: str,
    scope_types: tuple[str, ...],
    rules: dict[str, Rule],
) -> CheckFn:
    type_name = _type_name(expected)

    if sev in (Severity.WARNING, Severity.INFO, Severity.PERF):
        if nullable:
            pattern = f"{event_type}['{field}'] should be {type_name} or None"
        else:
            pattern = f"{event_type}['{field}'] should be {type_name}"
    else:
        if nullable:
            pattern = f"{event_type}['{field}'] must be None or {type_name}"
        else:
            pattern = f"{event_type}['{field}'] must be {type_name}"

    rule = Rule(
        rid,
        sev,
        summary or pattern,
        hint=hint,
        layer=layer,
        scope_types=scope_types,
    )
    rules[rid] = rule

    detail_prefix = pattern

    if nullable:

        def fn_type(ctx: ConnectionContext, msg: Message) -> None:
            if field in msg:
                val = msg[field]
                if val is not None and not isinstance(val, expected):
                    ctx.violation(
                        rule,
                        f"{detail_prefix}, got {type(val).__name__}",
                    )

    else:

        def fn_type(ctx: ConnectionContext, msg: Message) -> None:
            if field in msg:
                val = msg[field]
                if not isinstance(val, expected):
                    ctx.violation(
                        rule,
                        f"{detail_prefix}, got {type(val).__name__}",
                    )

    return fn_type


def _compile_headers_format(
    check: HeadersFormat,
    event_type: str,
    layer: str,
    scope_types: tuple[str, ...],
    rules: dict[str, Rule],
) -> CheckFn:
    field = check.field

    summary = check.summary or f"{event_type} headers format invalid"
    format_rule = Rule(
        check.format_rule_id,
        check.severity,
        summary,
        hint=check.hint,
        layer=layer,
        scope_types=scope_types,
    )
    rules[check.format_rule_id] = format_rule

    lowercase_rule: Rule | None = None
    if check.lowercase_rule_id:
        lowercase_rule = Rule(
            check.lowercase_rule_id,
            Severity.WARNING,
            "Header name should be lowercase",
            layer=layer,
            scope_types=scope_types,
        )
        rules[check.lowercase_rule_id] = lowercase_rule

    name_type_rule: Rule | None = None
    if check.name_type_rule_id:
        name_type_rule = Rule(
            check.name_type_rule_id,
            Severity.ERROR,
            "Header name must be bytes",
            layer=layer,
            scope_types=scope_types,
        )
        rules[check.name_type_rule_id] = name_type_rule

    value_type_rule: Rule | None = None
    if check.value_type_rule_id:
        value_type_rule = Rule(
            check.value_type_rule_id,
            Severity.ERROR,
            "Header value must be bytes",
            layer=layer,
            scope_types=scope_types,
        )
        rules[check.value_type_rule_id] = value_type_rule

    forbidden_pairs: list[tuple[bytes, Rule]] = []
    for fh in check.forbidden:
        fh_summary = fh.summary or f"{fh.name.decode()} header in response"
        fh_rule = Rule(
            fh.rule_id,
            fh.severity,
            fh_summary,
            hint=fh.hint,
            layer=layer,
            scope_types=scope_types,
        )
        rules[fh.rule_id] = fh_rule
        forbidden_pairs.append((fh.name, fh_rule))
    forbidden_tuple = tuple(forbidden_pairs)

    def fn_headers(ctx: ConnectionContext, msg: Message) -> None:
        if field not in msg:
            return
        headers = msg[field]
        validate_headers(
            ctx,
            headers,
            format_rule,
            lowercase_rule=lowercase_rule,
            name_type_rule=name_type_rule,
            value_type_rule=value_type_rule,
        )
        if forbidden_tuple:
            _check_forbidden_headers(ctx, headers, forbidden_tuple)

    return fn_headers


def _check_forbidden_headers(
    ctx: ConnectionContext,
    headers: Any,
    forbidden: tuple[tuple[bytes, Rule], ...],
) -> None:
    found: set[bytes] = set()
    try:
        for item in headers:
            if not isinstance(item, (list | tuple)) or len(item) != 2:
                return
            name = item[0]
            if isinstance(name, bytes):
                name_lower = name.lower()
                for fname, frule in forbidden:
                    if name_lower == fname and fname not in found:
                        ctx.violation(frule)
                        found.add(fname)
    except TypeError:
        return


def _type_name(t: type | tuple[type, ...]) -> str:
    if isinstance(t, tuple):
        return " or ".join(cls.__name__ for cls in t)
    return t.__name__
