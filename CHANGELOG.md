# Changelog

## 0.2.0 (2026-02-17)

### Features

- **162 validation rules** (was 75) across 12 layers — added Scope Fields,
  Extensions, and Semantic layers
- **Scope field validation** (layers 1-3): HTTP (HS-001..HS-028), WebSocket
  (WS-001..WS-025), Lifespan (LS-001..LS-004) — validates all scope dict fields
  per ASGI spec
- **Extension validator** (layer 10): gate checks for Server Push, Zero Copy Send,
  Path Send, Early Hints, Debug events (EX-001..EX-011)
- **Semantic validator** (layer 11): duplicate headers, missing Content-Type,
  Content-Length mismatch, Set-Cookie security, disconnect tracking,
  TTFB/lifecycle/body-size thresholds (SEM-001..SEM-011)
- **pytest plugin** (`pip install asgion[pytest]`):
  - `asgi_inspect` fixture — wrap ASGI apps with validation in tests
  - `@pytest.mark.asgi_validate` marker — auto-check violations at teardown
  - `--asgi-strict` / `--asgi-min-severity` CLI flags
- **Additional FSM rules**: HF-001, HF-009, HF-010, HF-012, WF-011, LF-009, LF-010

### Internal

- Scope checks compiled from declarative `ProtocolSpec.scope_checks`
- Configurable perf thresholds (TTFB, lifecycle, body size, chunk fragmentation)

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
