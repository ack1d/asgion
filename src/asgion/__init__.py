from importlib.metadata import version

from asgion.core._types import Severity
from asgion.core.config import (
    BUILTIN_PROFILES,
    AsgionConfig,
    ConfigError,
    load_config,
    load_user_profiles,
)
from asgion.core.inspector import Inspector
from asgion.core.rule import Rule
from asgion.core.violation import ASGIProtocolError, Violation
from asgion.core.wrapper import inspect
from asgion.trace import (
    FileStorage,
    MemoryStorage,
    TraceEvent,
    TraceRecord,
    TraceScope,
    TraceStorage,
    TraceSummary,
)

__version__ = version("asgion")


__all__ = [
    "BUILTIN_PROFILES",
    "ASGIProtocolError",
    "AsgionConfig",
    "ConfigError",
    "FileStorage",
    "Inspector",
    "MemoryStorage",
    "Rule",
    "Severity",
    "TraceEvent",
    "TraceRecord",
    "TraceScope",
    "TraceStorage",
    "TraceSummary",
    "Violation",
    "__version__",
    "inspect",
    "load_config",
    "load_user_profiles",
]
