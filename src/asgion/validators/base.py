"""Base validator interface and registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from asgion.core._types import Message, Scope
    from asgion.core.config import AsgionConfig
    from asgion.core.context import ConnectionContext


class BaseValidator:
    """Base class for all ASGI validators.

    Subclasses override one or more methods to validate specific aspects
    of the ASGI protocol. Each method receives the ConnectionContext which
    tracks state and collects violations.
    """

    def validate_scope(self, ctx: ConnectionContext, scope: Scope) -> None:
        """Validate the scope dict. Called once when connection starts."""

    def validate_receive(self, ctx: ConnectionContext, message: Message) -> None:
        """Validate a receive event (server -> app). Called per message."""

    def validate_send(self, ctx: ConnectionContext, message: Message) -> None:
        """Validate a send event (app -> server). Called per message."""

    def validate_complete(self, ctx: ConnectionContext) -> None:
        """Final validation after app coroutine exits. Called once."""


class ValidatorRegistry:
    """Registry of validators grouped by scope type."""

    def __init__(self) -> None:
        self._validators: dict[str, list[BaseValidator]] = {
            "http": [],
            "websocket": [],
            "lifespan": [],
        }
        self._global: list[BaseValidator] = []  # Applied to all scope types

    def register(
        self,
        validator: BaseValidator,
        scope_types: list[str] | None = None,
    ) -> None:
        """Register a validator for specific scope types, or globally."""
        if scope_types is None:
            self._global.append(validator)
        else:
            for st in scope_types:
                if st in self._validators:
                    self._validators[st].append(validator)

    def get_validators(self, scope_type: str) -> list[BaseValidator]:
        """Get all validators applicable to a scope type."""
        specific = self._validators.get(scope_type, [])
        return [*self._global, *specific]


def create_default_registry(config: AsgionConfig | None = None) -> ValidatorRegistry:
    """Create a registry with all built-in validators."""
    from asgion.spec import ALL_SPECS
    from asgion.validators.extension import ExtensionValidator
    from asgion.validators.general import GeneralValidator
    from asgion.validators.http_fsm import HTTPFSMValidator
    from asgion.validators.lifespan_fsm import LifespanFSMValidator
    from asgion.validators.spec_events import SpecEventValidator
    from asgion.validators.ws_fsm import WebSocketFSMValidator

    registry = ValidatorRegistry()

    # Layer 0: General (all scope types)
    registry.register(GeneralValidator())

    # Layers 4-6: Event validators (spec-driven)
    for protocol, compiled in ALL_SPECS.items():
        registry.register(SpecEventValidator(compiled), scope_types=[protocol])

    # Layers 7-9: FSM validators (manual)
    registry.register(HTTPFSMValidator(), scope_types=["http"])
    registry.register(WebSocketFSMValidator(), scope_types=["websocket"])
    registry.register(LifespanFSMValidator(), scope_types=["lifespan"])

    # Layer 10: Extension validator
    registry.register(ExtensionValidator(), scope_types=["http"])

    # Layer 11: Semantic validator
    from asgion.validators.semantic import SemanticValidator

    registry.register(SemanticValidator(config=config), scope_types=["http"])

    return registry
