# Changelog

## Unreleased

- ...

## 0.5.1 (2026-02-26)

### Features

- `asgion rules HF-002` — single rule lookup by ID with summary, hint, and layer.
- `asgion check --help` now documents exit codes: 0 (success), 1 (violations with `--strict`), 2 (runtime error).
- `asgion trace --min-severity` — filter violation markers by severity in text output.
- `asgion rules --format json` now includes `total_available` when filtering by `--layer` or `--severity`.

### Fixes

- `asgion check` summary footer: `Paths:` renamed to `Scopes:` — lifespan is a scope, not a path.
- `asgion trace`: violation markers now colored by severity (error=red, warning=yellow, info=cyan, perf=dim) instead of all-red.
- `asgion rules`: missing layers (Scope, Semantic, Extensions) now displayed — all 164 rules visible.
- `asgion trace`: application exceptions no longer crash the CLI or get silently swallowed; errors are reported and partial traces are shown.
- `--exclude-rules` now supports glob patterns (e.g. `SEM-*`), matching config file behavior.
- `NO_COLOR=""` now correctly disables colors per no-color.org spec.
- `--path` help text in `check` and `trace` unified: `ws:/path for WebSocket`.

## 0.5.0 (2026-02-26)

### Features

- **Trace engine** - record every `receive()`/`send()` as structured traces
  with nanosecond timestamps. Enable with `Inspector(app, trace=True)`:

  ```python
  inspector = Inspector(app, trace=True)
  # ... drive the app ...
  record = inspector.traces[0]
  record.scope.method      # "GET"
  record.scope.path        # "/api/users"
  record.summary.ttfb_ns   # time to first byte (ns)
  ```

- **`TraceStorage` protocol** - pluggable storage backends. Built-in:
  `MemoryStorage` (default) and `FileStorage` (one JSON file per trace).

- **Deterministic sampling** - `sample_rate` parameter on Inspector.
  Hash-based, same endpoint always produces the same decision for a given rate.

- **`asgion trace` CLI command** - record traces from the command line.
  Human-readable text output with color-coded phases (`receive` in blue,
  `send` in green), inline violation markers with severity
  (`← HF-002 (error)`), per-record severity breakdown
  (`Violations: 2 (1 error, 1 info)`).
  `--format json` for machine-readable output, `--out` for file storage.

- **CLI help** - usage examples and default values in all `--help` output.

- Export `load_config` and `load_user_profiles` in public API.

### Fixes

- CLI `check`/`trace`: WS runner now sends a `websocket.receive` message
  before disconnect, making the synthetic session realistic and avoiding
  app crashes on frameworks that expect data after accept (e.g. Starlette).

- CLI `check`: summary line now reports application errors instead of
  showing "No violations found" when a scope raised an exception.

### Docs

- **README** - concise landing-page style with highlights section,
  trace CLI output example.
- **`docs/configuration.md`** - configuration guide with minimal example,
  full TOML reference, profiles, rule filtering, and Python API.

### Internal

- `Inspector` uses two independent wrapper closures: fast path (`trace=False`)
  and traced path (`trace=True`). No runtime branching - selected once at init.
- O(1) per-message tracing hot path; heavy processing deferred to `finalize()`.

## 0.4.0 (2026-02-24)

### Internal

- `ConnectionContext`, `HTTPProtocolState`, `WebSocketProtocolState`,
  `LifespanProtocolState` converted to `@dataclass(slots=True)` — eliminates
  `__dict__` per-instance overhead and speeds up attribute access.
- `ConnectionContext.events` removed — the field was populated per-message but
  never read by any validator (dead code). For long-lived WebSocket connections
  this caused unbounded memory growth. `TraceRecorder` in v0.5.0 will provide
  proper event history via an efficient tuple-based format.
- `Inspector`: removed two per-message dict allocations (`ctx.events.append`)
  from the hot path.
- `SemanticValidator._check_response_headers`: header name checks converted
  from independent `if` branches to `elif` chain — semantically correct
  (a header has exactly one name) and reduces Cognitive Complexity.

### Breaking Changes

- `InspectedApp` (pytest plugin internal class) replaced by `Inspector`. Update
  type annotations: `asgi_inspect: Callable[..., InspectedApp]` →
  `asgi_inspect: Callable[..., Inspector]`. Import from `asgion` instead of
  `asgion.pytest_plugin`.

### Features

- **`Inspector` class** — stateful ASGI wrapper that accumulates violations
  across connections. Unlike `inspect()` (which returns a plain callable),
  `Inspector` keeps `violations` accessible after driving the app:
  ```python
  inspector = Inspector(app)
  # ... drive the app ...
  assert inspector.violations == []
  ```
  `Inspector` is also callable as an ASGI app directly (`await inspector(scope, receive, send)`).

- **User-defined profiles** — define custom profiles in `pyproject.toml` or
  `.asgion.toml`:
  ```toml
  [tool.asgion.profiles.ci]
  min_severity = "error"
  categories = ["http.fsm", "ws.fsm"]
  ```
  Use via `profile = "ci"` in config or `asgion check --profile ci` in CLI.

- **`load_user_profiles(path=None)`** — new public function that returns
  user-defined profiles from the config file.

- **`asgion check --profile`** now accepts user-defined profile names in addition
  to built-in ones (`strict`, `recommended`, `minimal`).

- `pytest` fixture `asgi_inspect` now returns `Inspector` instead of `InspectedApp`.
  `Inspector` exposes `.violations` and is callable as an ASGI app — fully
  backward-compatible for existing test code.

- `inspect()` is now a thin wrapper around `Inspector`. Behavior is unchanged.

## 0.3.0 (2026-02-19)

### Breaking Changes

- **Layer names renamed** - `categories` config values must be updated:
  - `"extension"` -> `"http.extension"`
  - `"semantic"` -> `"http.semantic"`

  This aligns both layers with the existing `http.fsm` / `ws.fsm` convention and
  enables `categories = ["http"]` to match all HTTP rules at once via prefix logic.

- **Rule ID renumbering** - all gaps in rule ID sequences eliminated. Affected series:
  - `HE`: 005->004, 010..028->005..023 (23 rules, sequential)
  - `HF`: 003..015->002..012 (12 rules, sequential)
  - `WE`: 002..023->001..016 (16 rules, sequential)
  - `LE`: 003,004,006->002,003,004 (4 rules, sequential)
  - Former `EX-001..EX-008` (renamed to `HE-021..HE-028` in the previous step,
    now `HE-016..HE-023` after renumbering). `EX-009..EX-011` remain unchanged.

### Features

- **WebSocket checking** - `asgion check` now supports WebSocket endpoints via `--path ws:/ws/chat`
  (or `wss:`). Without a prefix `--path` defaults to HTTP; `http:` and `https:` prefixes are also
  accepted for symmetry. The `asgi_inspect` pytest fixture now accepts `config=` parameter.

- **CLI deduplication** - repeated violations across multiple `--path` values are grouped in
  text output (`same as GET /a`) and JSON output (`count`, `paths` fields per violation;
  `summary.unique` added).

- **`--path` replaces `--url`** in `asgion check` — name now accurately reflects that a path
  (not a full URL) is expected. Protocol prefix determines scope type.

- **SEM-012** - CORS misconfiguration: `Access-Control-Allow-Origin: *` combined with
  `Access-Control-Allow-Credentials: true` is rejected by browsers (WARNING).
- **SEM-013** - `text/*` response missing `charset` in `Content-Type` header (INFO).
  Skipped for `text/event-stream` (SSE has its own framing).

- **AsgionConfig** - configurable rule filtering via `pyproject.toml` or `.asgion.toml`:
  `min_severity`, `include_rules`, `exclude_rules`, `categories`, thresholds.
  Supports glob patterns (`"SEM-*"`) in include/exclude lists.
- **Built-in profiles** (`strict` / `recommended` / `minimal`) available via
  `BUILTIN_PROFILES` dict or `--profile` CLI flag.
- **`--config FILE`** and **`--profile PROFILE`** CLI options for `asgion check`.
- `inspect()` accepts `config=AsgionConfig(...)` parameter.

### Internal

- **CI** - GitHub Actions workflow with four jobs: `lint` (ruff check + format), `typecheck` (mypy),
  `test` (pytest `-m "not integration"`, matrix 3.12/3.13/3.14, coverage upload to Codecov on 3.12),
  `integration` (pytest `-m integration`, runs after `test` passes). `uv sync --frozen` everywhere;
  `astral-sh/setup-uv@v7` with per-job caching (`enable-cache: true`, `cache-suffix`).
  Actions updated to latest: `actions/checkout@v6`, `astral-sh/setup-uv@v7`.
- **README** - added CI status badge and Codecov coverage badge.
- **Integration tests** - complete test suite across three frameworks using each framework's
  recommended approach: FastAPI (`httpx.AsyncClient` + `ASGITransport`), Litestar
  (`litestar.testing.AsyncTestClient`), Starlette (`httpx.AsyncClient` + `ASGITransport`, new).
  Each file skips independently via `pytest.importorskip`.
- **Detection tests** (`tests/test_detection.py`) - end-to-end tests verifying the full
  `inspect()` pipeline fires violations for non-compliant raw ASGI apps.

## 0.2.0 (2026-02-17)

### Features

- **162 validation rules** (was 75) across 12 layers — added Scope Fields,
  Extensions, and Semantic layers
- **Scope field validation** (layers 1-3): HTTP (HS-001..HS-028), WebSocket
  (WS-001..WS-025), Lifespan (LS-001..LS-004) — validates all scope dict fields
  per ASGI spec
- **Extension validator** (layer 10): gate checks for Server Push, Zero Copy Send,
  Path Send, Early Hints, Debug events (EX-009..EX-011; field rules were EX-001..EX-008, now HE-021..HE-028)
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
