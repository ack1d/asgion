# asgion

[![CI](https://github.com/ack1d/asgion/actions/workflows/ci.yml/badge.svg)](https://github.com/ack1d/asgion/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/ack1d/asgion/branch/main/graph/badge.svg)](https://codecov.io/gh/ack1d/asgion)
[![PyPI](https://img.shields.io/pypi/v/asgion)](https://pypi.org/project/asgion/)
[![Python](https://img.shields.io/pypi/pyversions/asgion)](https://pypi.org/project/asgion/)
[![License](https://img.shields.io/pypi/l/asgion)](https://github.com/ack1d/asgion/blob/main/LICENSE)

**ASGI protocol inspector** — validates your ASGI application against the
[ASGI specification](https://asgi.readthedocs.io/en/latest/) at runtime.
Catches protocol violations, state machine errors, and event schema mismatches
before they become production bugs.

Zero runtime dependencies. Python 3.12+.

## Quickstart

### Python API

```bash
pip install asgion
```

```python
from asgion import inspect

app = inspect(app)  # wrap any ASGI app — zero config
```

Use with any ASGI server:

```python
import uvicorn

uvicorn.run(inspect(app), host="127.0.0.1", port=8000)
```

### CLI

```bash
pip install asgion[cli]
asgion check myapp:app
```

## What It Catches

**164 rules** across 12 layers — scope fields, event schemas, state machines,
extensions, and semantic checks for HTTP, WebSocket, and Lifespan.

```
[G-005]  error    Message must be a dict
[HE-012] error    response.body 'body' must be bytes, got str
[HF-003] error    Duplicate http.response.start
[WE-008] warning  websocket.send has both 'bytes' and 'text' set
```

Every rule has an ID, severity, summary, and hint. See the full list:
[docs/rules.md](docs/rules.md)

## CLI Reference

### `asgion check`

```
asgion check APP_PATH [OPTIONS]
```

Check an ASGI app for protocol violations.

| Option | Description |
|--------|-------------|
| `APP_PATH` | Module:attribute path (e.g. `myapp:app`) |
| `--path PATH` | Paths to check (repeatable, default `/`). Prefix with protocol to set scope type: `http:/path`, `https:/path`, `ws:/path`, `wss:/path` |
| `--strict` | Exit 1 on any violations |
| `--format text\|json` | Output format (default `text`) |
| `--exclude-rules IDS` | Comma-separated rule IDs to skip |
| `--min-severity LEVEL` | Minimum severity: `perf`, `info`, `warning`, `error` |
| `--config FILE` | Path to `.asgion.toml` or `pyproject.toml` |
| `--profile PROFILE` | Rule filter profile: `strict`, `recommended`, `minimal` |
| `--no-color` | Disable ANSI colors (also respects `NO_COLOR` env) |
| `--no-lifespan` | Skip lifespan startup/shutdown checks |

```bash
asgion check myapp:app --path /api/users           # HTTP (default)
asgion check myapp:app --path ws:/ws/chat          # WebSocket
asgion check myapp:app --path /api --path ws:/ws   # both
```

Exit codes: `0` = clean, `1` = violations (with `--strict`), `2` = runtime error.

### `asgion rules`

```
asgion rules [OPTIONS]
```

List all validation rules.

| Option | Description |
|--------|-------------|
| `--format text\|json` | Output format (default `text`) |
| `--layer LAYER` | Filter by layer: `general`, `http`, `websocket`, `lifespan` |
| `--severity LEVEL` | Filter by severity: `perf`, `info`, `warning`, `error` |
| `--no-color` | Disable ANSI colors |

### `asgion --version`

Print version and exit.

## Python API

```python
from asgion import AsgionConfig, inspect

cfg = AsgionConfig(
    min_severity="warning",                # skip perf/info rules
    exclude_rules={"HE-012", "G-008"},     # suppress specific rules
    ttfb_threshold=2.0,                    # custom TTFB threshold (seconds)
)

wrapped = inspect(
    app,
    config=cfg,
    strict=False,                          # True to raise on violations
    on_violation=lambda v: print(v),       # real-time callback
    exclude_paths=["/health", "/metrics"], # skip these paths
)
```

Or select a built-in profile:

```python
from asgion import BUILTIN_PROFILES, inspect

app = inspect(app, config=BUILTIN_PROFILES["recommended"])  # warning+ only
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app` | `ASGIApp` | required | The ASGI application to wrap |
| `config` | `AsgionConfig` | `None` | Rule filter settings and thresholds |
| `strict` | `bool` | `False` | Raise `ASGIProtocolError` on any violation |
| `on_violation` | callback | `None` | Called with each `Violation` in real-time |
| `exclude_paths` | `list[str]` | `None` | Paths to skip validation |
| `exclude_rules` | `set[str]` | `None` | Rule IDs to suppress (additive to config) |
| `registry` | `ValidatorRegistry` | `None` | Custom validator registry |

### AsgionConfig

Can also be loaded from `pyproject.toml` or `.asgion.toml`:

```toml
[tool.asgion]
profile = "recommended"       # base profile: strict / recommended / minimal
exclude_rules = ["SEM-006"]   # suppress specific rules (supports globs: "SEM-*")
include_rules = ["HF-*"]      # allowlist — only these rules fire
categories = ["http"]         # filter by layer prefix ("http" matches http.fsm, http.semantic, …)
ttfb_threshold = 2.0          # SEM-006: TTFB limit (seconds)
lifecycle_threshold = 30.0    # SEM-007: total connection time (seconds)
body_size_threshold = 10485760  # SEM-008: response size (bytes)
```

### Violation

```python
@dataclass(frozen=True, slots=True)
class Violation:
    rule_id: str       # "HF-001", "G-010"
    severity: Severity # error, warning, info, perf
    message: str       # human-readable description
    hint: str          # suggestion for fixing
    scope_type: str    # "http", "websocket", "lifespan"
    path: str          # "/api/users"
    method: str        # "GET"
```

## pytest Plugin

```bash
pip install asgion[pytest]
```

```python
async def test_my_app(asgi_inspect):
    app = asgi_inspect(my_app)
    async with httpx.AsyncClient(transport=ASGITransport(app)) as client:
        resp = await client.get("/users")
    assert app.violations == []
```

Auto-check violations with a marker:

```python
@pytest.mark.asgi_validate(min_severity="error")
async def test_strict(asgi_inspect):
    app = asgi_inspect(my_app)
    # ... drive the app — violations checked automatically at teardown
```

Or enable globally for all tests using `asgi_inspect`:

```bash
pytest --asgi-strict
pytest --asgi-strict --asgi-min-severity warning
```

## Comparison

| Feature | asgion | asgiref.testing | Manual testing |
|---------|--------|-----------------|----------------|
| Scope validation | 71 rules | basic | none |
| Event schema checks | 43 rules | none | manual |
| State machine (FSM) | 34 rules | none | none |
| Semantic checks | 13 rules | none | none |
| Extension validation | 3 rules | none | none |
| pytest plugin | yes | no | n/a |
| Real-time callbacks | yes | no | n/a |
| CLI tool | yes | no | no |
| Zero dependencies | yes | no (asgiref) | n/a |
| Rule suppression | per-rule | no | n/a |

## Contributing

```bash
git clone https://github.com/ack1d/asgion.git
cd asgion
uv sync --group dev
uv run pytest              # run tests
uv run ruff check src/     # lint
uv run mypy src/           # type check
```

## License

MIT
