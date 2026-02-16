# asgion

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

**75 rules** across 7 layers — from basic scope validation to HTTP/WebSocket/Lifespan
state machine enforcement.

```
[G-005]  error    Message must be a dict
[HE-017] error    response.body 'body' must be bytes, got str
[HF-004] error    Duplicate http.response.start
[WE-012] warning  websocket.send has both 'bytes' and 'text' set
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
| `--url PATH` | URL paths to check (repeatable, default `/`) |
| `--strict` | Exit 1 on any violations |
| `--format text\|json` | Output format (default `text`) |
| `--exclude-rules IDS` | Comma-separated rule IDs to skip |
| `--min-severity LEVEL` | Minimum severity: `perf`, `info`, `warning`, `error` |
| `--no-color` | Disable ANSI colors (also respects `NO_COLOR` env) |
| `--no-lifespan` | Skip lifespan startup/shutdown checks |

Exit codes: `0` = clean, `1` = violations (with `--strict`), `2` = runtime error.

### `asgion rules`

```
asgion rules [OPTIONS]
```

List all 75 validation rules.

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
from asgion import inspect

wrapped = inspect(
    app,
    strict=False,                          # True to raise on violations
    on_violation=lambda v: print(v),       # real-time callback
    exclude_paths=["/health", "/metrics"], # skip these paths
    exclude_rules={"HE-012", "G-008"},     # suppress specific rules
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app` | `ASGIApp` | required | The ASGI application to wrap |
| `strict` | `bool` | `False` | Raise `ASGIProtocolError` on any violation |
| `on_violation` | callback | `None` | Called with each `Violation` in real-time |
| `exclude_paths` | `list[str]` | `None` | Paths to skip validation |
| `exclude_rules` | `set[str]` | `None` | Rule IDs to suppress |
| `registry` | `ValidatorRegistry` | `None` | Custom validator registry |

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

## Comparison

| Feature | asgion | asgiref.testing | Manual testing |
|---------|--------|-----------------|----------------|
| Scope validation | 14 rules | basic | none |
| Event schema checks | 40+ rules | none | manual |
| State machine (FSM) | 21 rules | none | none |
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
