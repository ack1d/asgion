from asgion.core._types import Severity
from asgion.core.rule import Rule

_LAYER = "general"
_SCOPES = ("http", "websocket", "lifespan")

G_001 = Rule("G-001", Severity.ERROR, "Scope must be a dict", layer=_LAYER, scope_types=_SCOPES)
G_002 = Rule(
    "G-002", Severity.ERROR, "Scope must contain key 'type'", layer=_LAYER, scope_types=_SCOPES
)
G_003 = Rule(
    "G-003", Severity.ERROR, "scope['type'] must be a str", layer=_LAYER, scope_types=_SCOPES
)
G_004 = Rule(
    "G-004",
    Severity.ERROR,
    "Unknown scope type",
    hint="Expected 'http', 'websocket', or 'lifespan'",
    layer=_LAYER,
    scope_types=_SCOPES,
)
G_005 = Rule("G-005", Severity.ERROR, "Message must be a dict", layer=_LAYER, scope_types=_SCOPES)
G_006 = Rule(
    "G-006", Severity.ERROR, "Message must contain key 'type'", layer=_LAYER, scope_types=_SCOPES
)
G_007 = Rule(
    "G-007", Severity.ERROR, "message['type'] must be a str", layer=_LAYER, scope_types=_SCOPES
)
G_008 = Rule(
    "G-008",
    Severity.ERROR,
    "NaN value in message",
    hint="ASGI spec forbids NaN in messages",
    layer=_LAYER,
    scope_types=_SCOPES,
)
G_009 = Rule(
    "G-009",
    Severity.ERROR,
    "Infinity value in message",
    hint="ASGI spec forbids Infinity in messages",
    layer=_LAYER,
    scope_types=_SCOPES,
)
G_010 = Rule(
    "G-010",
    Severity.ERROR,
    "Forbidden type in message",
    hint="ASGI messages may only contain: bytes, str, int, float, list, dict, bool, None",
    layer=_LAYER,
    scope_types=_SCOPES,
)
G_011 = Rule(
    "G-011",
    Severity.ERROR,
    "Scope must contain 'asgi' dict with version info",
    layer=_LAYER,
    scope_types=_SCOPES,
)
G_012 = Rule(
    "G-012",
    Severity.ERROR,
    "asgi['version'] must be '2.0' or '3.0'",
    layer=_LAYER,
    scope_types=_SCOPES,
)
G_013 = Rule(
    "G-013",
    Severity.WARNING,
    "asgi['spec_version'] should be a str",
    layer=_LAYER,
    scope_types=_SCOPES,
)
G_014 = Rule(
    "G-014",
    Severity.WARNING,
    "Message nesting exceeds maximum depth",
    layer=_LAYER,
    scope_types=_SCOPES,
)
