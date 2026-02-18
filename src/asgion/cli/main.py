"""CLI entry point - Click commands for asgion."""

from __future__ import annotations

import dataclasses
import sys

import click

from asgion import __version__
from asgion.cli._loader import LoadError, load_app
from asgion.cli._output import (
    format_json,
    format_rules_json,
    format_rules_text,
    format_text,
)
from asgion.cli._runner import run_check
from asgion.core._types import Severity
from asgion.core.config import BUILTIN_PROFILES, AsgionConfig, ConfigError, load_config
from asgion.rules import ALL_RULES


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", message="asgion %(version)s")
def cli() -> None:
    """asgion - ASGI protocol inspector."""


@cli.command()
@click.argument("app_path")
@click.option(
    "--path",
    "paths",
    multiple=True,
    default=("/",),
    help="Paths to check. Default is HTTP. Prefix with protocol to specify type: http:/path, https:/path, ws:/path, wss:/path.",
)
@click.option("--strict", is_flag=True, help="Exit 1 on any violations.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
@click.option("--exclude-rules", default="", help="Comma-separated rule IDs to exclude.")
@click.option(
    "--min-severity",
    type=click.Choice(["perf", "info", "warning", "error"]),
    default="perf",
    help="Minimum severity to report.",
)
@click.option("--no-color", is_flag=True, envvar="NO_COLOR", help="Disable ANSI colors.")
@click.option("--no-lifespan", is_flag=True, help="Skip lifespan checks.")
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(exists=False),
    help="Path to .asgion.toml or pyproject.toml config file.",
)
@click.option(
    "--profile",
    type=click.Choice(list(BUILTIN_PROFILES)),
    default=None,
    help="Rule filter profile (overrides config file profile).",
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
    """Check an ASGI app for protocol violations."""
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
        base = BUILTIN_PROFILES[profile]
        # CLI --profile overrides filter settings; preserve thresholds and
        # merge exclude_rules (config file exclusions are additive).
        config = dataclasses.replace(
            config,
            min_severity=base.min_severity,
            include_rules=base.include_rules,
            categories=base.categories,
            exclude_rules=base.exclude_rules | config.exclude_rules,
        )

    excluded = {r.strip() for r in exclude_rules.split(",") if r.strip()} if exclude_rules else None
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
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
@click.option("--no-color", is_flag=True, envvar="NO_COLOR", help="Disable ANSI colors.")
@click.option(
    "--layer",
    default=None,
    type=click.Choice(["general", "http", "ws", "lifespan"]),
    help="Filter by layer.",
)
@click.option(
    "--severity",
    "sev",
    default=None,
    type=click.Choice(["perf", "info", "warning", "error"]),
    help="Filter by severity.",
)
def rules(fmt: str, no_color: bool, layer: str | None, sev: str | None) -> None:
    """List all validation rules."""
    filtered = list(ALL_RULES)
    if layer is not None:
        filtered = [r for r in filtered if r.layer == layer or r.layer.startswith(layer + ".")]
    if sev is not None:
        severity = Severity(sev)
        filtered = [r for r in filtered if r.severity == severity]

    total = len(ALL_RULES) if (layer is not None or sev is not None) else None

    if fmt == "json":
        click.echo(format_rules_json(filtered))
    else:
        click.echo(format_rules_text(filtered, no_color=no_color, total=total))
