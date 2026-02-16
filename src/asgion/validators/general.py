import math
from typing import Any

from asgion.core._types import ScopeType
from asgion.core.context import ConnectionContext
from asgion.rules.general import (
    G_001,
    G_002,
    G_003,
    G_004,
    G_005,
    G_006,
    G_007,
    G_008,
    G_009,
    G_010,
    G_011,
    G_012,
    G_013,
    G_014,
)
from asgion.validators.base import BaseValidator

# Allowed types in ASGI messages (spec 3.0)
# NOTE: tuple is included despite the spec explicitly stating
# "Lists (tuples should be encoded as lists)" in the Events section.
# However, asgiref/typing.py defines headers, client, server as
# Iterable[tuple[...]] and all major frameworks (Django, Starlette, Litestar)
# send tuples. The canonical typing contradicts the spec text.
# Follow the typing and ecosystem reality.
_ALLOWED_TYPES = (bytes, str, int, float, list, dict, bool, type(None), tuple)

_MAX_DEPTH = 32


class GeneralValidator(BaseValidator):
    """Validates general ASGI rules (Layer 0)."""

    def validate_scope(self, ctx: ConnectionContext, scope: Any) -> None:
        if not isinstance(scope, dict):
            ctx.violation(G_001, f"Scope must be a dict, got {type(scope).__name__}")
            return

        if "type" not in scope:
            ctx.violation(G_002)
            return

        scope_type = scope["type"]
        if not isinstance(scope_type, str):
            ctx.violation(G_003, f"scope['type'] must be a str, got {type(scope_type).__name__}")
            return

        if scope_type not in ScopeType:
            ctx.violation(G_004, f"Unknown scope type: '{scope_type}'")

        if "asgi" not in scope:
            ctx.violation(G_011)
            return

        asgi = scope["asgi"]
        version = asgi.get("version")
        if version not in ("2.0", "3.0"):
            ctx.violation(G_012, f"asgi['version'] must be '2.0' or '3.0', got {version!r}")
        spec_version = asgi.get("spec_version")
        if spec_version is not None and not isinstance(spec_version, str):
            ctx.violation(
                G_013, f"asgi['spec_version'] should be a str, got {type(spec_version).__name__}"
            )

    def validate_receive(self, ctx: ConnectionContext, message: Any) -> None:
        self._validate_message(ctx, message, direction="receive")

    def validate_send(self, ctx: ConnectionContext, message: Any) -> None:
        self._validate_message(ctx, message, direction="send")

    def _validate_message(self, ctx: ConnectionContext, message: Any, direction: str) -> None:
        if not isinstance(message, dict):
            ctx.violation(
                G_005, f"{direction} message must be a dict, got {type(message).__name__}"
            )
            return

        if "type" not in message:
            ctx.violation(G_006, f"{direction} message must contain key 'type'")
            return

        msg_type = message["type"]
        if not isinstance(msg_type, str):
            ctx.violation(
                G_007,
                f"{direction} message['type'] must be a str, got {type(msg_type).__name__}",
            )

        self._check_values(ctx, message, path="message")

    def _check_values(self, ctx: ConnectionContext, obj: Any, path: str, depth: int = 0) -> None:
        """Recursively check message values for forbidden types."""
        if depth > _MAX_DEPTH:
            ctx.violation(G_014, f"Nesting exceeds {_MAX_DEPTH} at {path}")
            return

        if isinstance(obj, dict):
            for k, v in obj.items():
                self._check_values(ctx, v, path=f"{path}[{k!r}]", depth=depth + 1)
        elif isinstance(obj, list | tuple):
            for i, v in enumerate(obj):
                self._check_values(ctx, v, path=f"{path}[{i}]", depth=depth + 1)
        elif isinstance(obj, float):
            if math.isnan(obj):
                ctx.violation(G_008, f"NaN value found at {path}")
            if math.isinf(obj):
                ctx.violation(G_009, f"Infinity value found at {path}")
        elif not isinstance(obj, _ALLOWED_TYPES):
            ctx.violation(G_010, f"Forbidden type {type(obj).__name__} at {path}")
