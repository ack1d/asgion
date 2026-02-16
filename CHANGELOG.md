# Changelog

## 0.1.0 (2026-02-16)

Initial release.

### Features

- **75 validation rules** across 7 layers: General, HTTP Events, HTTP FSM,
  WebSocket Events, WebSocket FSM, Lifespan Events, Lifespan FSM
- **`inspect()` wrapper** - wrap any ASGI app with zero-config protocol validation
- **Declarative spec engine** - event schemas compiled at import time from
  protocol specifications
- **State machine validators** - HTTP, WebSocket, and Lifespan FSM enforcement
- **CLI** (`asgion check`, `asgion rules`) — check apps from the command line
- **JSON output** - machine-readable violation reports
- **Real-time callbacks** - `on_violation` for streaming violation detection
- **Rule suppression** - `exclude_rules` to skip specific checks
- **Path exclusion** - `exclude_paths` to skip validation for health checks, etc.
- **Strict mode** - `ASGIProtocolError` raised on any violation
- **Zero runtime dependencies** - pure Python 3.12+
