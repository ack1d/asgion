from importlib.metadata import version

from asgion.core._types import Severity
from asgion.core.config import BUILTIN_PROFILES, AsgionConfig, ConfigError
from asgion.core.context import ConnectionContext
from asgion.core.rule import Rule
from asgion.core.violation import ASGIProtocolError, Violation
from asgion.core.wrapper import inspect
from asgion.validators.base import BaseValidator, ValidatorRegistry

__version__ = version("asgion")


__all__ = [
    "BUILTIN_PROFILES",
    "ASGIProtocolError",
    "AsgionConfig",
    "BaseValidator",
    "ConfigError",
    "ConnectionContext",
    "Rule",
    "Severity",
    "ValidatorRegistry",
    "Violation",
    "__version__",
    "inspect",
]
