"""CLI entry point - Click commands for asgion."""

from __future__ import annotations

import dataclasses
import sys

import click

from asgion import __version__
from asgion.cli._loader import LoadError, load_app
from asgion.cli._output import (
    format_json,
    format_rule_detail,
    format_rules_json,
    format_rules_text,
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
@click.argument("app_path", metavar="APP_PATH")
@click.option(
    "--path",
    "paths",
    multiple=True,
    default=("/",),
    help=("Paths to check (repeatable).  [default: /]  Prefix: ws:/path for WebSocket."),
)
@click.option("--strict", is_flag=True, help="Exit 1 on any violation found.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format.",
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
    help="Minimum severity to report.",
)
@click.option("--no-color", is_flag=True, envvar="NO_COLOR", help="Disable ANSI colors.")
@click.option("--no-lifespan", is_flag=True, help="Skip lifespan startup/shutdown checks.")
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
    app_path: str,
    paths: tuple[str, ...],
    strict: bool,
    fmt: str,
    exclude_rules: str,
    min_severity: str,
    no_color: bool,
    no_lifespan: bool,
    config_path: str | None,
    profile: str | None,
) -> None:
    """Check an ASGI app for protocol violations.

    APP_PATH is a Python import path (module:attribute).

    \b
    Examples:
      asgion check myapp:app
      asgion check myapp:app --path /api/users --path ws:/ws/chat
      asgion check myapp:app --strict --min-severity warning
      asgion check myapp:app --profile recommended --format json

    \b
    Exit codes:
      0  success (without --strict, always 0)
      1  violations found (only with --strict)
      2  runtime error (bad module path, invalid config, etc.)
    """
    try:
        app = load_app(app_path)
    except LoadError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    try:
        config: AsgionConfig = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"Error: invalid config: {exc}", err=True)
        sys.exit(2)

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
                expanded.update(rid for rid in all_ids if fnmatch(rid, pattern))
            else:
                expanded.add(pattern)
        excluded = expanded
    severity = Severity(min_severity)

    report = run_check(
        app,
        app_path=app_path,
        paths=paths,
        config=config,
        exclude_rules=excluded,
        run_lifespan=not no_lifespan,
    )

    if fmt == "json":
        click.echo(format_json(report, min_severity=severity))
    else:
        click.echo(format_text(report, min_severity=severity, no_color=no_color))

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
    type=click.Choice(["general", "http", "ws", "lifespan"]),
    help="Show only rules from this layer.",
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
      asgion rules
      asgion rules HF-002
      asgion rules --layer http --severity error
      asgion rules --format json
    """
    if rule_id is not None:
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
@click.argument("app_path", metavar="APP_PATH")
@click.option(
    "--path",
    "paths",
    multiple=True,
    default=("/",),
    help=("Paths to trace (repeatable).  [default: /]  Prefix: ws:/path for WebSocket."),
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
    "--min-severity",
    default="perf",
    type=click.Choice(["perf", "info", "warning", "error"]),
    show_default=True,
    help="Minimum severity for violation markers.",
)
def trace(
    app_path: str,
    paths: tuple[str, ...],
    fmt: str,
    no_color: bool,
    trace_dir: str | None,
    max_body_size: int,
    no_lifespan: bool,
    min_severity: str,
) -> None:
    """Record every receive()/send() as structured traces.

    APP_PATH is a Python import path (module:attribute).

    Each trace captures the full ASGI lifecycle of a connection:
    scope, events with nanosecond timestamps, and a summary.

    \b
    Examples:
      asgion trace myapp:app
      asgion trace myapp:app --format json
      asgion trace myapp:app --path /api/users --out ./traces/
      asgion trace myapp:app --path ws:/ws/chat
    """
    try:
        app = load_app(app_path)
    except LoadError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    records = run_trace(
        app,
        paths=paths,
        trace_dir=trace_dir,
        max_body_size=max_body_size,
        run_lifespan=not no_lifespan,
    )

    severity = Severity(min_severity)

    if trace_dir is None:
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
