# asgion

[![CI](https://github.com/ack1d/asgion/actions/workflows/ci.yml/badge.svg)](https://github.com/ack1d/asgion/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/ack1d/asgion/branch/main/graph/badge.svg)](https://codecov.io/gh/ack1d/asgion)
[![PyPI](https://img.shields.io/pypi/v/asgion)](https://pypi.org/project/asgion/)
[![Python](https://img.shields.io/pypi/pyversions/asgion)](https://pypi.org/project/asgion/)
[![License](https://img.shields.io/pypi/l/asgion)](https://github.com/ack1d/asgion/blob/main/LICENSE)

ASGI protocol inspector and trace engine.
Validates HTTP, WebSocket & Lifespan state machines, event schemas, and scope fields.

## Highlights

- **Comprehensive validation** — scope fields, event schemas, state machines, semantic checks
- **HTTP, WebSocket, Lifespan** — all three ASGI protocols covered
- **Trace engine** — record every `receive()`/`send()` with nanosecond timestamps and inline violation markers
- **CLI, Python API, pytest plugin** — fits any workflow
- **Zero runtime dependencies** — pure Python 3.12+
- **O(1) per message** — safe for hot paths, no overhead when tracing is off

## Quickstart

```bash
pip install asgion[cli]
asgion check myapp:app
```

```
── GET / ─────────────────────────────────────────────────────
  [HF-003] error: Duplicate http.response.start
    hint: Only one response.start is allowed per HTTP connection
  [HE-012] error: response.body 'body' must be bytes, got str

2 violations (2 error)
```

See the [full rule list](docs/rules.md) for all available rules and their descriptions.

## Python API

```python
from asgion import Inspector

inspector = Inspector(app)
# ... drive the app via httpx, TestClient, etc. ...
assert inspector.violations == []
```

As middleware:

```python
from asgion import inspect

uvicorn.run(inspect(app))
```

## Tracing

Record the full ASGI lifecycle for debugging and analysis:

```python
inspector = Inspector(app, trace=True)
async with httpx.AsyncClient(transport=ASGITransport(inspector)) as client:
    await client.get("/api/users")

record = inspector.traces[0]
record.scope.method      # "GET"
record.scope.path        # "/api/users"
record.summary.ttfb_ns   # time to first byte (ns)
```

```bash
asgion trace myapp:app --out ./traces/   # save as JSON files
```

```
asgion trace myapp:app
```

```
TRACE  GET / (0.070ms, TTFB 0.042ms)

     0.020ms  send     http.response.body  4 bytes  ← HF-002 (error)
     0.042ms  send     http.response.start  200  (+0.022ms)  ← SEM-002 (info)
     0.059ms  send     http.response.body  5 bytes  (+0.016ms)

  Events: 3  |  Violations: 2 (1 error, 1 info)
```

## Pytest Plugin

```bash
pip install asgion[pytest]
```

```python
async def test_my_app(asgi_inspect):
    inspector = asgi_inspect(my_app)
    async with httpx.AsyncClient(transport=ASGITransport(inspector)) as client:
        await client.get("/users")
    assert inspector.violations == []
```

```bash
pytest --asgi-strict   # auto-check all tests
```

## Configuration

Via `pyproject.toml`, `.asgion.toml`, or Python API.
See [configuration docs](docs/configuration.md) and [full rule list](docs/rules.md).

```toml
[tool.asgion]
profile = "recommended"
exclude_rules = ["SEM-006"]
```

## Contributing

```bash
git clone https://github.com/ack1d/asgion.git
cd asgion
uv sync --group dev
uv run pytest
```

If you have [Task](https://taskfile.dev) installed: `task check` runs lint, typecheck, and tests.

## License

MIT