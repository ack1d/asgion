from asgion.core.rule import Rule
from asgion.spec._compiler import compile_spec
from asgion.spec._http import HTTP_SPEC
from asgion.spec._lifespan import LIFESPAN_SPEC
from asgion.spec._protocol import CompiledSpec
from asgion.spec._websocket import WS_SPEC

_HTTP = compile_spec(HTTP_SPEC)
_WS = compile_spec(WS_SPEC)
_LIFESPAN = compile_spec(LIFESPAN_SPEC)

ALL_SPECS: dict[str, CompiledSpec] = {
    "http": _HTTP,
    "websocket": _WS,
    "lifespan": _LIFESPAN,
}

SPEC_RULES: dict[str, Rule] = {**_HTTP.rules, **_WS.rules, **_LIFESPAN.rules}

__all__ = ["ALL_SPECS", "SPEC_RULES"]
