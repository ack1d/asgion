from dataclasses import dataclass

from asgion.core._types import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    """Metadata for a single validation rule.

    Rule instances are pure data - they describe *what* a rule checks,
    not *how* to check it.  Validators reference Rule objects by import.

    Example::

        HF_007 = Rule(
            id="HF-007",
            severity=Severity.ERROR,
            summary="Send after client disconnected",
            hint="Check for http.disconnect before sending response",
            layer="http.fsm",
            scope_types=("http",),
        )
    """

    id: str
    severity: Severity
    summary: str
    hint: str = ""
    layer: str = ""
    scope_types: tuple[str, ...] = ()

    def __str__(self) -> str:
        return f"[{self.id}] {self.summary}"
