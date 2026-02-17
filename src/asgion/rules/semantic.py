from asgion.core._types import Severity
from asgion.core.rule import Rule

_LAYER = "semantic"
_SCOPES = ("http",)

SEM_001 = Rule(
    "SEM-001",
    Severity.WARNING,
    "Duplicate Content-Type header in response",
    hint="Only one Content-Type header should be sent",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_002 = Rule(
    "SEM-002",
    Severity.INFO,
    "No Content-Type header on 2xx response",
    hint="Responses with a body should include a Content-Type header",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_003 = Rule(
    "SEM-003",
    Severity.WARNING,
    "Content-Length does not match actual body size",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_004 = Rule(
    "SEM-004",
    Severity.WARNING,
    "Set-Cookie without Secure flag on http:// scheme",
    hint="Cookies on plaintext HTTP can be intercepted",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_005 = Rule(
    "SEM-005",
    Severity.INFO,
    "App completed without receiving http.disconnect",
    hint="Long-running handlers should listen for http.disconnect to detect client drops",
    layer=_LAYER,
    scope_types=_SCOPES,
)
