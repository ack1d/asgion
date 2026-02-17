from asgion.core._types import Severity
from asgion.core.rule import Rule

_LAYER = "extension"
_SCOPES = ("http",)

EX_009 = Rule(
    "EX-009",
    Severity.ERROR,
    "Extension event sent without corresponding scope extension",
    hint="scope['extensions'] must contain the extension key",
    layer=_LAYER,
    scope_types=_SCOPES,
)
EX_010 = Rule(
    "EX-010",
    Severity.ERROR,
    "http.response.early_hint sent after http.response.start",
    hint="Early hints must be sent before the response starts",
    layer=_LAYER,
    scope_types=_SCOPES,
)
EX_011 = Rule(
    "EX-011",
    Severity.ERROR,
    "http.response.debug sent after http.response.start",
    hint="Debug info should be sent before the response starts",
    layer=_LAYER,
    scope_types=_SCOPES,
)
