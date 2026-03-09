"""CLI entry point - Click commands for asgion."""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import click

from asgion import __version__
from asgion.cli._loader import LoadError, load_app
from asgion.cli._output import (
    format_json,
    format_junit,
    format_rule_detail,
    format_rules_json,
    format_rules_text,
    format_sarif,
    format_text,
    format_trace_json,
    format_trace_text,
)
from asgion.cli._runner import run_check
from asgion.cli._trace import run_trace
from asgion.core._types import Severity
from asgion.core.config import (
    BUILTIN_PROFILES,
    AsgionConfig,
    ConfigError,
    load_config,
    load_user_profiles,
)
from asgion.rules import ALL_RULES, RULES


def _parse_headers(raw: tuple[str, ...]) -> list[tuple[bytes, bytes]]:
    result: list[tuple[bytes, bytes]] = []
    for h in raw:
        if ":" not in h:
            click.echo(f"Warning: header {h!r} has no colon, expected 'Name: value'", err=True)
            continue
        name, _, value = h.partition(":")
        name = name.strip()
        if not name:
            continue
        result.append((name.lower().encode(), value.strip().encode()))
    return result


def _resolve_app_path(app_path: str | None, config: AsgionConfig) -> str:
    if app_path is not None:
        return app_path
    if config.app:
        return config.app
    cmd = click.style("asgion check myapp:app", bold=True)
    cfg = click.style('app = "myapp:app"', bold=True)
    click.echo(
        f"Error: missing APP_PATH argument.\n\n"
        f"  Provide it as an argument:\n"
        f"    {cmd}\n\n"
        f"  Or set it in config (.asgion.toml or pyproject.toml [tool.asgion]):\n"
        f"    {cfg}",
        err=True,
    )
    sys.exit(2)


def _load(app_path: str) -> object:
    try:
        return load_app(app_path)
    except LoadError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)


def _prepare_request(
    method: str,
    raw_headers: tuple[str, ...],
    raw_body: str | None,
) -> tuple[str, list[tuple[bytes, bytes]] | None, bytes]:
    return (
        method.upper(),
        _parse_headers(raw_headers) if raw_headers else None,
        raw_body.encode() if raw_body is not None else b"",
    )


_LAYERS = [
    "general",
    "http",
    "http.scope",
    "http.events",
    "http.fsm",
    "http.semantic",
    "http.extension",
    "ws",
    "ws.scope",
    "ws.events",
    "ws.fsm",
    "lifespan",
    "lifespan.scope",
    "lifespan.events",
    "lifespan.fsm",
]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", message="asgion %(version)s")
def cli() -> None:
    """asgion - ASGI protocol inspector.

    Validates scope fields, event schemas, state machines, and semantic
    constraints for HTTP, WebSocket, and Lifespan protocols.

    APP_PATH is a Python import path in the form module:attribute,
    e.g. myapp:app or myapp.main:application.
    """


@cli.command()
@click.argument("app_path", metavar="APP_PATH", required=False, default=None)
@click.option(
    "--path",
    "paths",
    multiple=True,
    default=(),
    help="Paths to check (repeatable).  [default: /]  Prefix: ws:/path, METHOD:/path.",
)
@click.option("--strict", is_flag=True, help="Exit 1 on any violation found.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif", "junit"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--select",
    default="",
    help="Comma-separated rule allowlist (e.g. HF-*,SEM-001). Only matching rules run.",
)
@click.option(
    "--exclude-rules",
    default="",
    help="Comma-separated rule IDs to suppress (e.g. SEM-006,SEM-009).",
)
@click.option(
    "--min-severity",
    type=click.Choice(["perf", "info", "warning", "error"]),
    default="perf",
    show_default=True,
    help="Minimum severity to report. Note: --profile may set a higher floor.",
)
@click.option("--no-color", is_flag=True, envvar="NO_COLOR", help="Disable ANSI colors.")
@click.option(
    "--layer",
    "layers",
    multiple=True,
    type=click.Choice(_LAYERS),
    help="Only check rules from this layer (repeatable). Prefix match: 'http' includes http.*.",
)
@click.option("--no-lifespan", is_flag=True, help="Skip lifespan startup/shutdown checks.")
@click.option(
    "--method",
    default="GET",
    show_default=True,
    help="Default HTTP method for paths without a method prefix.",
)
@click.option(
    "-H",
    "--header",
    "raw_headers",
    multiple=True,
    help="Custom header (repeatable). Format: 'Name: value'.",
)
@click.option(
    "-d",
    "--body",
    "raw_body",
    default=None,
    help="Request body string (sent as-is in http.request).",
)
@click.option(
    "--timeout",
    default=5.0,
    show_default=True,
    type=float,
    help="Timeout per scope in seconds.",
)
@click.option("-q", "--quiet", is_flag=True, help="Suppress all output; exit code only.")
@click.option(
    "--out",
    default=None,
    type=click.Path(),
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(exists=False),
    help="Path to .asgion.toml or pyproject.toml. Auto-detected if omitted.",
)
@click.option(
    "--profile",
    default=None,
    help=(
        "Profile name (overrides config file). "
        f"Built-in: {', '.join(BUILTIN_PROFILES)}. "
        "User-defined profiles are loaded from config."
    ),
)
def check(
    app_path: str | None,
    paths: tuple[str, ...],
    strict: bool,
    fmt: str,
    select: str,
    exclude_rules: str,
    min_severity: str,
    no_color: bool,
    layers: tuple[str, ...],
    no_lifespan: bool,
    method: str,
    raw_headers: tuple[str, ...],
    raw_body: str | None,
    timeout: float,
    quiet: bool,
    out: str | None,
    config_path: str | None,
    profile: str | None,
) -> None:
    """Check an ASGI app for protocol violations.

    APP_PATH is a Python import path (module:attribute).
    If omitted, reads from config file (app = "myapp:app").

    \b
    Examples:
      asgion check myapp:app \n
      asgion check                    # uses app from config \n
      asgion check myapp:app --path /api/users --path ws:/ws/chat \n
      asgion check myapp:app --strict --min-severity warning \n
      asgion check myapp:app --path "POST:/api/users" -H "Content-Type: application/json" -d '{}' \n

    \b
    Exit codes:
      0  success (without --strict, always 0) \n
      1  violations found (only with --strict) \n
      2  runtime error (bad module path, invalid config, etc.) \n
    """
    try:
        config: AsgionConfig = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"Error: invalid config: {exc}", err=True)
        sys.exit(2)

    app_path = _resolve_app_path(app_path, config)
    app = _load(app_path)

    if profile is not None:
        user_profiles = load_user_profiles(config_path)
        all_profiles = BUILTIN_PROFILES | user_profiles
        base = all_profiles.get(profile)
        if base is None:
            known = ", ".join(f'"{p}"' for p in all_profiles)
            click.echo(f"Error: unknown profile {profile!r}. Known profiles: {known}", err=True)
            sys.exit(2)
        # CLI --profile overrides filter settings; preserve thresholds and
        # merge exclude_rules (config file exclusions are additive).
        config = dataclasses.replace(
            config,
            min_severity=base.min_severity,
            include_rules=base.include_rules,
            categories=base.categories,
            exclude_rules=base.exclude_rules | config.exclude_rules,
        )

    if layers:
        config = dataclasses.replace(config, categories=config.categories | frozenset(layers))

    if select:
        from fnmatch import fnmatch

        cli_include = frozenset(r.strip() for r in select.split(",") if r.strip())
        all_ids = [r.id for r in ALL_RULES]
        for pattern in cli_include:
            if any(c in pattern for c in "*?["):
                if not any(fnmatch(rid, pattern) for rid in all_ids):
                    click.echo(f"Warning: no rules match pattern: {pattern}", err=True)
            elif pattern not in RULES:
                click.echo(f"Warning: unknown rule: {pattern}", err=True)
        config = dataclasses.replace(config, include_rules=config.include_rules | cli_include)

    raw_excluded = (
        {r.strip() for r in exclude_rules.split(",") if r.strip()} if exclude_rules else None
    )
    excluded: set[str] | None = None
    if raw_excluded:
        from fnmatch import fnmatch

        expanded: set[str] = set()
        all_ids = [r.id for r in ALL_RULES]
        for pattern in raw_excluded:
            if any(c in pattern for c in "*?["):
                matched = [rid for rid in all_ids if fnmatch(rid, pattern)]
                if not matched:
                    click.echo(f"Warning: no rules match pattern: {pattern}", err=True)
                expanded.update(matched)
            else:
                if pattern not in RULES:
                    click.echo(f"Warning: unknown rule: {pattern}", err=True)
                expanded.add(pattern)
        excluded = expanded
    severity = Severity(min_severity)
    if paths:
        final_paths = paths
    elif config.paths:
        final_paths = config.paths
    else:
        final_paths = ("/",)

    default_method, headers, body = _prepare_request(method, raw_headers, raw_body)

    report = run_check(
        app,
        app_path=app_path,
        paths=final_paths,
        config=config,
        exclude_rules=excluded,
        run_lifespan=not no_lifespan,
        default_method=default_method,
        headers=headers,
        body=body,
        scope_timeout=timeout,
    )

    if out is not None:
        if fmt == "json":
            file_output = format_json(report, min_severity=severity)
        elif fmt == "sarif":
            file_output = format_sarif(report, min_severity=severity)
        elif fmt == "junit":
            file_output = format_junit(report, min_severity=severity)
        else:
            file_output = format_text(report, min_severity=severity, no_color=True)
        Path(out).write_text(file_output + "\n")

    if not quiet and out is None:
        if fmt == "json":
            output = format_json(report, min_severity=severity)
        elif fmt == "sarif":
            output = format_sarif(report, min_severity=severity)
        elif fmt == "junit":
            output = format_junit(report, min_severity=severity)
        else:
            output = format_text(report, min_severity=severity, no_color=no_color)
        click.echo(output)

    violations = report.filtered(severity)
    if strict and violations:
        sys.exit(1)


@cli.command()
@click.argument("rule_id", required=False, default=None)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option("--no-color", is_flag=True, envvar="NO_COLOR", help="Disable ANSI colors.")
@click.option(
    "--layer",
    default=None,
    type=click.Choice(_LAYERS),
    help="Show only rules from this layer. Prefix match: 'http' includes http.*.",
)
@click.option(
    "--severity",
    "sev",
    default=None,
    type=click.Choice(["perf", "info", "warning", "error"]),
    help="Show only rules with this severity.",
)
def rules(
    rule_id: str | None,
    fmt: str,
    no_color: bool,
    layer: str | None,
    sev: str | None,
) -> None:
    """List all validation rules, or show details for a single rule.

    Without arguments, prints every rule grouped by layer.
    With RULE_ID, shows details for that specific rule.

    \b
    Examples:
      asgion rules \n
      asgion rules HF-002 \n
      asgion rules --layer http --severity error \n
      asgion rules --format json \n

    \b
    Exit codes:
      0  success \n
      2  unknown rule ID \n
    """
    if rule_id is not None:
        if layer is not None or sev is not None:
            click.echo("Warning: --layer/--severity ignored when RULE_ID is specified", err=True)
        rule = RULES.get(rule_id)
        if rule is None:
            click.echo(f"Error: unknown rule: {rule_id}", err=True)
            sys.exit(2)
        if fmt == "json":
            click.echo(format_rules_json([rule]))
        else:
            click.echo(format_rule_detail(rule, no_color=no_color))
        return

    filtered = list(ALL_RULES)
    if layer is not None:
        filtered = [r for r in filtered if r.layer == layer or r.layer.startswith(layer + ".")]
    if sev is not None:
        severity = Severity(sev)
        filtered = [r for r in filtered if r.severity == severity]

    total = len(ALL_RULES) if (layer is not None or sev is not None) else None

    if fmt == "json":
        click.echo(format_rules_json(filtered, total=total))
    else:
        click.echo(format_rules_text(filtered, no_color=no_color, total=total))


@cli.command()
@click.argument("app_path", metavar="APP_PATH", required=False, default=None)
@click.option(
    "--path",
    "paths",
    multiple=True,
    default=(),
    help="Paths to trace (repeatable).  [default: /]  Prefix: ws:/path, METHOD:/path.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format (ignored when --out is used).",
)
@click.option("--no-color", is_flag=True, envvar="NO_COLOR", help="Disable ANSI colors.")
@click.option(
    "--out",
    "trace_dir",
    default=None,
    type=click.Path(),
    help="Directory for trace JSON files. Prints to stdout if omitted.",
)
@click.option(
    "--max-body-size",
    default=65536,
    show_default=True,
    type=int,
    help="Max response body to record per event (bytes).",
)
@click.option("--no-lifespan", is_flag=True, help="Skip lifespan startup/shutdown tracing.")
@click.option(
    "--method",
    default="GET",
    show_default=True,
    help="Default HTTP method for paths without a method prefix.",
)
@click.option(
    "-H",
    "--header",
    "raw_headers",
    multiple=True,
    help="Custom header (repeatable). Format: 'Name: value'.",
)
@click.option(
    "-d",
    "--body",
    "raw_body",
    default=None,
    help="Request body string (sent as-is in http.request).",
)
@click.option(
    "--timeout",
    default=5.0,
    show_default=True,
    type=float,
    help="Timeout per scope in seconds.",
)
@click.option("--strict", is_flag=True, help="Exit 1 on any violation found.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress all output; exit code only.")
@click.option(
    "--min-severity",
    default="perf",
    type=click.Choice(["perf", "info", "warning", "error"]),
    show_default=True,
    help="Minimum severity for violation markers.",
)
def trace(
    app_path: str | None,
    paths: tuple[str, ...],
    fmt: str,
    no_color: bool,
    trace_dir: str | None,
    max_body_size: int,
    no_lifespan: bool,
    method: str,
    raw_headers: tuple[str, ...],
    raw_body: str | None,
    timeout: float,
    strict: bool,
    quiet: bool,
    min_severity: str,
) -> None:
    """Record every receive()/send() as structured traces.

    APP_PATH is a Python import path (module:attribute).
    If omitted, reads from config file (app = "myapp:app").

    Each trace captures the full ASGI lifecycle of a connection:
    scope, events with nanosecond timestamps, and a summary.

    \b
    Examples:
      asgion trace myapp:app \n
      asgion trace                    # uses app from config \n
      asgion trace myapp:app --format json \n
      asgion trace myapp:app --path "POST:/api/users" -d '{}' \n
      asgion trace myapp:app --path ws:/ws/chat \n

    \b
    Exit codes:
      0  success (without --strict, always 0) \n
      1  violations found (only with --strict) \n
      2  runtime error (bad module path, etc.) \n
    """
    try:
        trace_config = load_config()
    except ConfigError:
        trace_config = AsgionConfig()

    app_path = _resolve_app_path(app_path, trace_config)
    app = _load(app_path)

    final_paths = paths or trace_config.paths or ("/",)

    default_method, headers, body = _prepare_request(method, raw_headers, raw_body)

    records = run_trace(
        app,
        paths=final_paths,
        trace_dir=trace_dir,
        max_body_size=max_body_size,
        run_lifespan=not no_lifespan,
        default_method=default_method,
        headers=headers,
        body=body,
        scope_timeout=timeout,
    )

    severity = Severity(min_severity)

    if trace_dir is None and not quiet:
        if fmt == "json":
            click.echo(format_trace_json(records))
        else:
            click.echo(
                format_trace_text(
                    records,
                    app_path=app_path,
                    no_color=no_color,
                    min_severity=severity,
                )
            )

    if strict:
        from asgion.core._types import SEVERITY_LEVEL

        min_level = SEVERITY_LEVEL[severity]
        has_violations = any(
            SEVERITY_LEVEL[RULES[v.rule_id].severity] >= min_level
            for r in records
            for v in r.summary.violations
            if v.rule_id in RULES
        )
        if has_violations:
            sys.exit(1)


_INIT_BODY = """\
# ASGI app import path - allows running `asgion check` without arguments
# app = "myapp:app"

# Built-in profile: "strict" (all rules), "recommended" (warning+), "minimal" (error only)
profile = "recommended"

# Rule filtering - control which rules are checked
# min_severity = "perf"           # ignore rules below this level
# include_rules = []              # allowlist, e.g. ["HF-*", "SEM-001"]
# exclude_rules = []              # denylist, e.g. ["SEM-006", "SEM-009"]
# categories = []                 # layer filter, e.g. ["http.fsm", "http.semantic"]

# Paths to check (CLI --path overrides these)
# paths = ["/", "/api/users", "POST:/api/data", "ws:/ws/chat"]

# Semantic thresholds - when to trigger performance/size warnings
# ttfb_threshold = 5.0            # SEM-006: max time to first byte (seconds)
# lifecycle_threshold = 30.0      # SEM-007: max request lifecycle (seconds)
# body_size_threshold = 10_485_760  # SEM-008: max response body (bytes, 10 MB)
# buffer_chunk_threshold = 1_048_576  # SEM-009: min chunk size (bytes, 1 MB)
# body_delivery_threshold = 10.0  # SEM-010: max body delivery time (seconds)
# chunk_count_threshold = 100     # SEM-011: max body chunks per response
"""


@cli.command()
@click.option("--pyproject", is_flag=True, help="Print [tool.asgion] block for pyproject.toml.")
@click.option("--force", is_flag=True, help="Overwrite existing .asgion.toml.")
def init(pyproject: bool, force: bool) -> None:
    """Generate a default asgion configuration file.

    \b
    Examples:
      asgion init                # create .asgion.toml \n
      asgion init --pyproject    # print [tool.asgion] block to stdout \n
      asgion init --force        # overwrite existing .asgion.toml \n

    \b
    Exit codes:
      0  success \n
      2  file already exists (without --force) \n
    """
    if pyproject:
        if force:
            click.echo(
                "Warning: --force has no effect with --pyproject (output goes to stdout)", err=True
            )
        toml_path = Path("pyproject.toml")
        if toml_path.exists():
            import tomllib

            with toml_path.open("rb") as f:
                data = tomllib.load(f)
            if "asgion" in data.get("tool", {}):
                click.echo(
                    "Warning: pyproject.toml already contains [tool.asgion]",
                    err=True,
                )
        click.echo(f"[tool.asgion]\n{_INIT_BODY}")
        return

    target = Path(".asgion.toml")
    if target.exists() and not force:
        flag = click.style("--force", bold=True)
        click.echo(
            f"Error: {target} already exists. Use {flag} to overwrite.",
            err=True,
        )
        sys.exit(2)

    target.write_text(f"# asgion configuration\n# https://github.com/ack1d/asgion\n\n{_INIT_BODY}")
    click.echo(f"Created {target}")
