# Configuration

asgion works out of the box with no configuration. All settings are optional —
add them only when you need to customize rule filtering, severity thresholds,
or inspection behavior.

## Config File

asgion looks for configuration in this order:

1. `.asgion.toml` in the current directory (then parent directories)
2. `[tool.asgion]` section in `pyproject.toml`

A `pyproject.toml` without `[tool.asgion]` acts as a project root marker and
stops the search (same convention as ruff/mypy).

Most projects only need a profile and a few excluded rules:

```toml
[tool.asgion]
profile = "recommended"
exclude_rules = ["SEM-006", "SEM-009"]
```

### Full Reference

All available options with defaults:

```toml
[tool.asgion]
# Base profile: "strict" (all rules), "recommended" (warning+), "minimal" (error only)
profile = "strict"

# Minimum severity to report: "perf", "info", "warning", "error"
min_severity = "perf"

# Rule allowlist — if set, only these rules are active (supports globs)
# include_rules = ["HF-*", "WF-*"]

# Rule denylist — suppress specific rules (supports globs)
# exclude_rules = ["SEM-006", "SEM-009"]

# Layer filter — only check these categories (prefix matching)
# categories = ["http.fsm", "ws.fsm"]

# Semantic validator thresholds
ttfb_threshold = 5.0            # SEM-006: TTFB limit (seconds)
lifecycle_threshold = 30.0      # SEM-007: total connection time (seconds)
body_size_threshold = 10485760  # SEM-008: response body size (bytes)
buffer_chunk_threshold = 1048576  # SEM-009: single-chunk buffering (bytes)
body_delivery_threshold = 10.0  # SEM-010: body delivery time (seconds)
chunk_count_threshold = 100     # SEM-011: max body chunks before warning
```

## Profiles

### Built-in Profiles

| Profile | `min_severity` | Description |
|---------|---------------|-------------|
| `strict` | `perf` | All rules, all severities (default) |
| `recommended` | `warning` | Warnings and errors only |
| `minimal` | `error` | Errors only |

### User-Defined Profiles

Define custom profiles in your config file:

```toml
[tool.asgion.profiles.ci]
min_severity = "error"
categories = ["http.fsm", "ws.fsm"]

[tool.asgion.profiles.dev]
min_severity = "info"
exclude_rules = ["SEM-006", "SEM-009"]
```

Use via CLI:

```bash
asgion check myapp:app --profile ci
```

Or in Python:

```python
from asgion import Inspector, load_user_profiles

profiles = load_user_profiles()
inspector = Inspector(app, config=profiles["ci"])
```

## Rule Filtering

Rules are filtered in this order:

1. **`min_severity`** — rules below this level are skipped
2. **`categories`** — if set, rule's layer must match a prefix
3. **`include_rules`** — if set, rule ID must match the allowlist
4. **`exclude_rules`** — rule ID must not match the denylist

Both `include_rules` and `exclude_rules` support glob patterns:

```toml
exclude_rules = ["SEM-*"]       # suppress all semantic rules
include_rules = ["HF-*", "WF-*"]  # only FSM rules
```

### Categories

Categories use prefix matching. `"http"` matches all HTTP layers:

| Category | Matches |
|----------|---------|
| `"http"` | `http.scope`, `http.events`, `http.fsm`, `http.extension`, `http.semantic` |
| `"http.fsm"` | `http.fsm` only |
| `"ws"` | `ws.scope`, `ws.events`, `ws.fsm` |
| `"lifespan"` | `lifespan.scope`, `lifespan.events`, `lifespan.fsm` |
| `"general"` | `general` |

## Python API

The simplest way — reuse your TOML config:

```python
from asgion import Inspector, load_config

inspector = Inspector(app, config=load_config())
```

Or load from a specific path:

```python
cfg = load_config("path/to/.asgion.toml")
```

For programmatic configuration, build `AsgionConfig` directly. Set-like fields
take `frozenset` (the config object is immutable):

```python
from asgion import AsgionConfig, Inspector

cfg = AsgionConfig(
    min_severity="warning",
    exclude_rules=frozenset({"SEM-006", "SEM-009"}),
)

inspector = Inspector(app, config=cfg)
```

## CLI

Run `asgion <command> --help` for full option list.
