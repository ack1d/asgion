from asgion.core._types import Severity
from asgion.core.rule import Rule

_LAYER = "http.fsm"
_SCOPES = ("http",)

HF_001 = Rule(
    "HF-001",
    Severity.ERROR,
    "http.response.start was never sent",
    hint="Application must send exactly one http.response.start per request",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_003 = Rule(
    "HF-003",
    Severity.ERROR,
    "http.response.body sent without preceding http.response.start",
    hint="Send http.response.start before any http.response.body",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_004 = Rule(
    "HF-004",
    Severity.ERROR,
    "Duplicate http.response.start",
    hint="http.response.start must be sent exactly once per request",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_006 = Rule(
    "HF-006",
    Severity.ERROR,
    "http.response.body sent after response was already completed",
    hint="Do not send body after more_body=False",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_007 = Rule(
    "HF-007",
    Severity.ERROR,
    "Send after client disconnected",
    hint="Check for http.disconnect before sending response",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_008 = Rule(
    "HF-008",
    Severity.INFO,
    "App exited without completing response body",
    hint="Ensure http.response.body with more_body=False is sent",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_009 = Rule(
    "HF-009",
    Severity.INFO,
    "Received http.request after body was already complete",
    hint="After more_body=False, further receives return http.disconnect",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_010 = Rule(
    "HF-010",
    Severity.ERROR,
    "trailers=True in response.start but no http.response.trailers sent",
    hint="Send http.response.trailers after the final response body",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_011 = Rule(
    "HF-011",
    Severity.ERROR,
    "Trailers sent without trailers=True in response.start",
    hint="Set trailers=True in http.response.start to use trailer headers",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_012 = Rule(
    "HF-012",
    Severity.INFO,
    "Streaming response body (more_body=True)",
    hint="Application is sending chunked response body",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_014 = Rule(
    "HF-014",
    Severity.WARNING,
    "HEAD request response has non-empty body",
    hint="HEAD responses must not include a body",
    layer=_LAYER,
    scope_types=_SCOPES,
)
HF_015 = Rule(
    "HF-015",
    Severity.WARNING,
    "Response has body when status code forbids it",
    hint="1xx/204/304 responses must not include a body",
    layer=_LAYER,
    scope_types=_SCOPES,
)
