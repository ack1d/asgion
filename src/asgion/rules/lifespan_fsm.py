from asgion.core._types import Severity
from asgion.core.rule import Rule

_LAYER = "lifespan.fsm"
_SCOPES = ("lifespan",)

LF_001 = Rule(
    "LF-001",
    Severity.ERROR,
    "lifespan.startup received in unexpected state",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_002 = Rule(
    "LF-002",
    Severity.ERROR,
    "lifespan.startup.complete/failed sent in wrong state",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_003 = Rule(
    "LF-003",
    Severity.ERROR,
    "Duplicate lifespan.startup.complete",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_004 = Rule(
    "LF-004",
    Severity.ERROR,
    "startup.complete and startup.failed are mutually exclusive",
    hint="Send exactly one of startup.complete or startup.failed",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_005 = Rule(
    "LF-005",
    Severity.ERROR,
    "lifespan.shutdown received before startup.complete",
    hint="Shutdown should only occur after successful startup",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_006 = Rule(
    "LF-006",
    Severity.ERROR,
    "lifespan.shutdown.complete/failed sent in wrong state",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_007 = Rule(
    "LF-007",
    Severity.ERROR,
    "shutdown.complete and shutdown.failed are mutually exclusive",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_008 = Rule(
    "LF-008",
    Severity.INFO,
    "App exited during shutdown without sending complete/failed",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_009 = Rule(
    "LF-009",
    Severity.WARNING,
    "App exited during startup without sending startup.complete or startup.failed",
    hint="An exception during startup is not the same as startup.failed — send the proper signal",
    layer=_LAYER,
    scope_types=_SCOPES,
)
LF_010 = Rule(
    "LF-010",
    Severity.INFO,
    "Lifespan state dict is available for sharing state with requests",
    hint="state is mutable in lifespan scope and shallow-copied to request scopes",
    layer=_LAYER,
    scope_types=_SCOPES,
)
