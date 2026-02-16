from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from asgion.core._types import Severity


@dataclass(frozen=True, slots=True)
class FieldRequired:
    """Field must be present in the message."""

    field: str
    rule_id: str
    severity: Severity = Severity.ERROR
    summary: str = ""
    hint: str = ""


@dataclass(frozen=True, slots=True)
class FieldType:
    """Field value must be of the correct type."""

    field: str
    expected: type | tuple[type, ...]
    rule_id: str
    nullable: bool = False
    severity: Severity = Severity.ERROR
    summary: str = ""
    hint: str = ""


@dataclass(frozen=True, slots=True)
class FieldValue:
    """Field value must pass a custom check function."""

    field: str
    check: Callable[[Any], str | None]  # None = OK, str = error detail
    rule_id: str
    severity: Severity = Severity.WARNING
    summary: str = ""
    hint: str = ""


@dataclass(frozen=True, slots=True)
class ExactlyOneNonNull:
    """Exactly one of two fields must be non-None."""

    field_a: str
    field_b: str
    rule_id: str
    severity: Severity = Severity.ERROR
    summary: str = ""
    hint: str = ""


@dataclass(frozen=True, slots=True)
class ForbiddenHeader:
    """A header name that must not appear."""

    name: bytes
    rule_id: str
    severity: Severity = Severity.WARNING
    summary: str = ""
    hint: str = ""


@dataclass(frozen=True, slots=True)
class HeadersFormat:
    """Headers must be iterable of ``(bytes, bytes)`` pairs."""

    field: str
    format_rule_id: str
    lowercase_rule_id: str = ""
    forbidden: tuple[ForbiddenHeader, ...] = ()
    severity: Severity = Severity.ERROR
    summary: str = ""
    hint: str = ""


type CheckSpec = FieldRequired | FieldType | FieldValue | ExactlyOneNonNull | HeadersFormat
