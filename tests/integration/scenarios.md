# Integration Test Scenarios

Integration tests answer two questions:

1. **False positive check** - does asgion stay silent when wrapping a well-behaved framework?
2. **Detection check** - does asgion correctly fire a violation when something is actually wrong?

All tests run with `BUILTIN_PROFILES["recommended"]` (`min_severity=WARNING`),
which reflects realistic production usage and avoids noise from INFO/PERF rules.

---

## What we test and why

### Happy Path (false positive check)

Verifies asgion produces no violations on the most common real-world HTTP patterns.

| Scenario | Why it matters |
|---|---|
| GET -> 200 JSON | Baseline: normal request/response cycle |
| POST with binary body -> 200 echo | Ensures request body reading doesn't disturb validation state |
| GET -> 404 (route not found) | Framework error responses must not look like protocol violations |
| GET -> 418 (explicit HTTPException) | Custom 4xx raised by the app - valid response, no violations |
| GET -> 500 (unhandled exception) | Framework swallows the exception and responds; asgion must not fire on the lifecycle |

### Status Code Semantics (false positive check)

204 and 304 responses are special: HTTP forbids a body, but ASGI apps still send
`http.response.body` with `body=b""` as a protocol terminator. asgion must not treat
this empty terminator as a violation.

| Scenario | Why it matters |
|---|---|
| GET -> 204, framework sends `body=b""` | `b""` is not a body - it's ASGI's way to signal end of response |
| GET -> 304, framework sends `body=b""` | Same as 204 - must not trigger HF-012 |

> HF-012 ("Response has body when status code forbids it") fires only when
> `total_body_bytes > 0`. An empty terminator is not counted.

### Method Semantics (false positive check)

HEAD requests: the HTTP spec requires no body in the response, but the ASGI spec
says the *server* (e.g. uvicorn) is responsible for stripping the body - not the app.

| Scenario | Framework behavior | asgion result |
|---|---|---|
| HEAD - FastAPI | Sends full body; uvicorn strips it at transport layer | HF-011 fires at INFO level - invisible with `recommended` |
| HEAD - Litestar | Uses `@head` decorator, sends no body at ASGI level | No violations at any level |
| HEAD - Starlette | GET handler registered for both GET and HEAD; framework sends no body | No violations at any level |

> HF-011 is INFO severity precisely because both behaviors are valid per ASGI spec.

### Streaming (false positive check)

Streaming responses send multiple `http.response.body` messages with `more_body=True`,
then a final one with `more_body=False`. The FSM and semantic validators must handle
this sequence without false positives.

| Scenario | Why it matters |
|---|---|
| Multi-chunk streaming (3 chunks) | Validates HF-010 (streaming info), SEM-009/SEM-011 don't fire at WARNING+ |
| Empty streaming response (0 chunks) | Generator yields nothing - framework still terminates the response correctly |

### Redirects (false positive check)

A redirect response (307/302) is a complete, valid HTTP exchange:
`response.start` (3xx) + `response.body` (empty) + `more_body=False`.

| Scenario | Why it matters |
|---|---|
| 3xx redirect, client doesn't follow | One complete request/response cycle |
| 3xx redirect followed -> 200 | Two complete request/response cycles through the same wrapped app |

### State Isolation (false positive check)

Each request must get its own `ConnectionContext`. Violations, counters, and phase
state from one request must never bleed into another.

| Scenario | Why it matters |
|---|---|
| 3 sequential requests | Violations list must stay empty across all three, not accumulate |
| 3 concurrent requests (`asyncio.gather`) | Parallel coroutines must use separate contexts, not share state |

### Lifespan (false positive check)

Most production apps use lifespan for startup/shutdown (DB connections, background tasks).
asgion must validate the lifespan protocol correctly and stay silent when the app
behaves well.

| Scenario | Why it matters |
|---|---|
| startup.complete -> shutdown.complete | Lifespan scope validation fires; no LS-xxx false positives |

> FastAPI and Starlette tests drive lifespan manually via `drive_lifespan()` in `conftest.py`,
> which sends startup -> waits for startup.complete -> sends shutdown -> waits for shutdown.complete.
> Litestar tests use `AsyncTestClient` as a context manager, which drives lifespan automatically.

### Detection (violation expected)

These deliberately introduce a protocol violation and assert asgion catches it.

| Scenario | Expected violation | Why it matters |
|---|---|---|
| Response with `Content-Length: 3` but body is 5 bytes | SEM-003 | Validates the semantic validator catches real mismatches from app code |

> Duplicate headers (SEM-001) and missing Content-Type (SEM-002) are not easily
> triggered via standard framework APIs - frameworks always set these correctly.
> They are covered in `tests/test_semantic.py` as unit tests.

---

## Test clients

| Framework | Client | Notes |
|---|---|---|
| FastAPI | `httpx.AsyncClient` + `ASGITransport` | Per FastAPI docs recommendation for async tests |
| Litestar | `litestar.testing.AsyncTestClient` | Per Litestar docs; handles lifespan automatically; G-011/LS-002 excluded - `AsyncTestClient` omits the `asgi` version dict from scope |
| Starlette | `httpx.AsyncClient` + `ASGITransport` | Per Starlette docs async recommendation |