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
SEM_006 = Rule(
    "SEM-006",
    Severity.PERF,
    "Slow time to first byte",
    hint="Response started more than 5s after receiving the request",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_007 = Rule(
    "SEM-007",
    Severity.PERF,
    "Total request lifecycle exceeded threshold",
    hint="Connection took more than 30s from start to completion",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_008 = Rule(
    "SEM-008",
    Severity.PERF,
    "Large response body",
    hint="Response body exceeds 10 MB; consider streaming or compression",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_009 = Rule(
    "SEM-009",
    Severity.INFO,
    "Response body not streamed",
    hint="Large body sent in a single chunk; consider streaming with more_body=True",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_010 = Rule(
    "SEM-010",
    Severity.PERF,
    "Slow response body delivery",
    hint="Time from response start to body complete exceeds 10s",
    layer=_LAYER,
    scope_types=_SCOPES,
)
SEM_011 = Rule(
    "SEM-011",
    Severity.INFO,
    "Excessive body chunk fragmentation",
    hint="Response sent in more than 100 chunks; consider larger writes",
    layer=_LAYER,
    scope_types=_SCOPES,
)
