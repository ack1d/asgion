from asgion.core._types import Severity
from asgion.core.rule import Rule

_LAYER = "ws.fsm"
_SCOPES = ("websocket",)

WF_001 = Rule(
    "WF-001",
    Severity.ERROR,
    "websocket.connect received in unexpected state",
    hint="websocket.connect should be the first message",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_002 = Rule(
    "WF-002",
    Severity.ERROR,
    "websocket.accept sent in wrong state",
    hint="Send accept only after receiving websocket.connect",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_003 = Rule(
    "WF-003",
    Severity.ERROR,
    "websocket.send before websocket.accept",
    hint="Accept the WebSocket connection before sending data",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_004 = Rule(
    "WF-004",
    Severity.ERROR,
    "websocket.send after websocket.close was sent",
    hint="Cannot send data after closing the connection",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_005 = Rule(
    "WF-005",
    Severity.ERROR,
    "Send/close after websocket.disconnect",
    hint="Client has disconnected, cannot send data",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_006 = Rule(
    "WF-006",
    Severity.ERROR,
    "Duplicate websocket.accept",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_007 = Rule(
    "WF-007",
    Severity.INFO,
    "websocket.close sent before accept - will result in HTTP 403",
    hint="This is valid for rejecting connections",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_008 = Rule(
    "WF-008",
    Severity.ERROR,
    "send() called after websocket.close",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_009 = Rule(
    "WF-009",
    Severity.ERROR,
    "websocket.http.response.start sent in wrong state",
    hint="HTTP denial response can only be sent before accepting",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_010 = Rule(
    "WF-010",
    Severity.ERROR,
    "websocket.http.response.body without preceding http.response.start",
    layer=_LAYER,
    scope_types=_SCOPES,
)
WF_012 = Rule(
    "WF-012",
    Severity.WARNING,
    "websocket.receive after connection closed",
    layer=_LAYER,
    scope_types=_SCOPES,
)
