from asgion.core.rule import Rule
from asgion.rules import (
    extension,
    general,
    http_fsm,
    lifespan_fsm,
    semantic,
    ws_fsm,
)
from asgion.spec import SPEC_RULES


def _collect_rules(*modules: object) -> dict[str, Rule]:
    """Collect all Rule instances from the given modules."""
    rules: dict[str, Rule] = {}
    for module in modules:
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, Rule):
                if obj.id in rules:
                    msg = f"Duplicate rule ID: {obj.id}"
                    raise ValueError(msg)
                rules[obj.id] = obj
    return rules


_MANUAL_RULES: dict[str, Rule] = _collect_rules(
    general,
    http_fsm,
    ws_fsm,
    lifespan_fsm,
    extension,
    semantic,
)

RULES: dict[str, Rule] = {**_MANUAL_RULES, **SPEC_RULES}
ALL_RULES: list[Rule] = sorted(RULES.values(), key=lambda r: r.id)

__all__ = ["ALL_RULES", "RULES"]
