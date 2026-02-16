from typing import Any

from asgion.core.context import ConnectionContext
from asgion.core.rule import Rule


def validate_headers(
    ctx: ConnectionContext,
    headers: Any,
    rule: Rule,
    *,
    lowercase_rule: Rule | None = None,
    name_type_rule: Rule | None = None,
    value_type_rule: Rule | None = None,
) -> None:
    """Validate headers format: iterable of ``(bytes, bytes)`` pairs.

    Args:
        ctx: Connection context to record violations on.
        headers: The headers value to validate.
        rule: Rule for structural issues (not iterable, bad pair format).
        lowercase_rule: Optional rule for non-lowercase header names.
        name_type_rule: Optional separate rule for header name type errors.
            Falls back to ``rule`` if not provided.
        value_type_rule: Optional separate rule for header value type errors.
            Falls back to ``rule`` if not provided.

    """
    _name_rule = name_type_rule or rule
    _value_rule = value_type_rule or rule
    try:
        for item in headers:
            if not isinstance(item, (list | tuple)) or len(item) != 2:
                ctx.violation(rule, "Headers must be an iterable of 2-element [name, value] pairs")
                return
            name, value = item
            if not isinstance(name, bytes):
                ctx.violation(_name_rule, f"Header name must be bytes, got {type(name).__name__}")
            if not isinstance(value, bytes):
                ctx.violation(
                    _value_rule, f"Header value must be bytes, got {type(value).__name__}"
                )
            if lowercase_rule is not None and isinstance(name, bytes) and name != name.lower():
                ctx.violation(lowercase_rule, f"Header name should be lowercase: {name!r}")
    except TypeError:
        ctx.violation(rule, f"Headers must be iterable, got {type(headers).__name__}")
