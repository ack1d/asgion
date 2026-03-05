# asgion

[![CI](https://github.com/ack1d/asgion/actions/workflows/ci.yml/badge.svg)](https://github.com/ack1d/asgion/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/ack1d/asgion/branch/main/graph/badge.svg)](https://codecov.io/gh/ack1d/asgion)
[![PyPI](https://img.shields.io/pypi/v/asgion)](https://pypi.org/project/asgion/)
[![Python](https://img.shields.io/pypi/pyversions/asgion)](https://pypi.org/project/asgion/)
[![License](https://img.shields.io/pypi/l/asgion)](https://github.com/ack1d/asgion/blob/main/LICENSE)

ASGI protocol inspector and trace engine.
Catch subtle protocol violations your tests miss — before they hit production.

## Why asgion?

ASGI apps can pass all tests while still violating the protocol:

- Sending response body before `http.response.start`
- Writing to a closed WebSocket connection
- Exiting without completing a streaming response
- Returning malformed event payloads

Frameworks catch some of this. asgion validates the full ASGI contract — state machines, event schemas, scope fields, and semantic constraints across HTTP, WebSocket, and Lifespan.

## Highlights

- **Full ASGI contract validation** — 163 rules across HTTP, WebSocket, and Lifespan
- **Trace engine** — record every `receive()`/`send()` with nanosecond timestamps and inline violation markers
- **CI-ready** — deterministic exit codes and JSON output
- **CLI, Python API, pytest plugin** — fits any workflow
- **Zero runtime dependencies** — pure Python 3.12+
- **O(1) per message** — safe for hot paths, no overhead when tracing is off

Works with any ASGI app: FastAPI, Starlette, Litestar, Django (ASGI), or bare ASGI handlers.

## Quickstart

Get started in under a minute:

```bash
pip install asgion[cli]
```

Given a buggy app that sends body before `http.response.start`:

```python
# myapp.py
async def app(scope, receive, send):
    if scope["type"] == "http":
        await send({"type": "http.response.body", "body": b"oops"})       # wrong order
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"hello"})
```

**Check** finds protocol violations:

```bash
asgion check myapp:app
```

```
CHECK  myapp:app

── GET / ─────────────────────────────────────────────────────────
  [HF-002] error: http.response.body sent without preceding http.response.start
    hint: Send http.response.start before any http.response.body
  [SEM-002] info: No Content-Type header on 2xx response
    hint: Responses with a body should include a Content-Type header

2 violations (1 error, 1 info)  |  709µs
```

What is `HF-002`? **Look up** any rule directly:

```bash
asgion rules HF-002
```

```
RULE  [HF-002] error
  http.response.body sent without preceding http.response.start
    hint: Send http.response.start before any http.response.body

  layer: http.fsm
  applies to: http
```

**Trace** shows the full event timeline for the same app:

```bash
asgion trace myapp:app
```

```
TRACE  GET / (88µs, TTFB 54µs)

        26µs  send     http.response.body  4 bytes  ← HF-002 (error)
        54µs  send     http.response.start  200  (+28µs)  ← SEM-002 (info)
        75µs  send     http.response.body  5 bytes  (+21µs)

  Events: 3  |  Violations: 2 (1 error, 1 info)
```

```bash
asgion trace myapp:app --min-severity error   # only error-level markers
asgion trace myapp:app --out ./traces/        # save as JSON files
```

**Filter, export, target specific endpoints:**

```bash
asgion check myapp:app --select "HF-*" --min-severity warning
asgion check myapp:app --path /api/users --path "POST:/api/users" -H "Content-Type: application/json"
asgion check myapp:app --format sarif --out report.sarif   # GitHub Code Scanning
asgion check myapp:app --format junit --out report.xml     # Jenkins / GitLab CI
```

**Bootstrap a config file:**

```bash
asgion init              # creates .asgion.toml with commented-out defaults
asgion init --pyproject  # prints [tool.asgion] block to stdout
```

Exit codes: 0 = clean, 1 = violations (`--strict`), 2 = runtime error. See `asgion check --help`.
App exceptions and timeouts are reported but do not affect exit codes — only protocol violations do.

See the [full rule list](docs/rules.md) for all 163 rules and their descriptions.

## Python API

```python
from asgion import Inspector

inspector = Inspector(app)
# ... drive the app via httpx, TestClient, etc. ...
assert inspector.violations == []  # fails if any protocol violation occurred
```

With tracing:

```python
inspector = Inspector(app, trace=True)
async with httpx.AsyncClient(transport=ASGITransport(inspector)) as client:
    await client.get("/api/users")

record = inspector.traces[0]
record.scope.method      # "GET"
record.scope.path        # "/api/users"
record.summary.ttfb_ns   # time to first byte (ns)
```

As middleware:

```python
from asgion import inspect

uvicorn.run(inspect(app))
```

## Pytest Plugin

Integrate protocol validation directly into your test suite:

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

## CI Integration

### GitHub Action

```yaml
# .github/workflows/asgion.yml
name: ASGI Check
on: [push, pull_request]
jobs:
  asgion:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ack1d/asgion@v0
        with:
          app: myapp:app
          strict: true
          format: sarif
```

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ack1d/asgion
    rev: v0.6.0  # update with: pre-commit autoupdate
    hooks:
      - id: asgion
        args: [myapp:app, --strict]
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