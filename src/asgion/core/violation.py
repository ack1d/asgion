from dataclasses import dataclass
from typing import Any

from asgion.core._types import Severity


@dataclass(frozen=True, slots=True)
class Violation:
    """A single ASGI protocol violation detected by asgion."""

    rule_id: str
    severity: Severity
    message: str
    hint: str = ""
    scope_type: str = ""
    path: str = ""
    method: str = ""
    timestamp: float = 0.0
    context: dict[str, Any] | None = None


class ASGIProtocolError(Exception):
    """Raised in strict mode when ASGI violations are detected."""

    def __init__(self, violations: list[Violation]) -> None:
        self.violations = violations
        count = len(violations)
        errors = sum(1 for v in violations if v.severity == Severity.ERROR)
        super().__init__(f"ASGI protocol error: {errors} errors in {count} violations")
