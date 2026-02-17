from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from asgion import inspect
from asgion.core._types import Severity
from asgion.core.config import (
    BUILTIN_PROFILES,
    AsgionConfig,
    ConfigError,
    _parse_config,
    load_config,
)
from asgion.core.rule import Rule

# Helpers

_PERF_RULE = Rule(id="X-001", severity=Severity.PERF, summary="perf rule", layer="http.fsm")
_INFO_RULE = Rule(id="X-002", severity=Severity.INFO, summary="info rule", layer="http.fsm")
_WARN_RULE = Rule(id="X-003", severity=Severity.WARNING, summary="warn rule", layer="semantic")
_ERR_RULE = Rule(id="X-004", severity=Severity.ERROR, summary="error rule", layer="http.scope")


# AsgionConfig defaults


def test_config_defaults() -> None:
    cfg = AsgionConfig()
    assert cfg.min_severity == Severity.PERF
    assert cfg.include_rules == frozenset()
    assert cfg.exclude_rules == frozenset()
    assert cfg.categories == frozenset()
    assert cfg.ttfb_threshold == 5.0
    assert cfg.lifecycle_threshold == 30.0
    assert cfg.body_size_threshold == 10 * 1024 * 1024
    assert cfg.buffer_chunk_threshold == 1 * 1024 * 1024
    assert cfg.body_delivery_threshold == 10.0
    assert cfg.chunk_count_threshold == 100


# AsgionConfig.allows(): severity filtering


def test_allows_passes_rule_at_min_severity() -> None:
    cfg = AsgionConfig(min_severity=Severity.WARNING)
    assert cfg.allows(_WARN_RULE) is True


def test_allows_passes_rule_above_min_severity() -> None:
    cfg = AsgionConfig(min_severity=Severity.WARNING)
    assert cfg.allows(_ERR_RULE) is True


def test_allows_blocks_rule_below_min_severity() -> None:
    cfg = AsgionConfig(min_severity=Severity.WARNING)
    assert cfg.allows(_PERF_RULE) is False
    assert cfg.allows(_INFO_RULE) is False


def test_allows_default_min_severity_passes_perf() -> None:
    cfg = AsgionConfig()
    assert cfg.allows(_PERF_RULE) is True


# AsgionConfig.allows(): categories filtering


def test_allows_no_categories_passes_any_layer() -> None:
    cfg = AsgionConfig(categories=frozenset())
    assert cfg.allows(_PERF_RULE) is True  # layer="http.fsm"
    assert cfg.allows(_WARN_RULE) is True  # layer="semantic"


def test_allows_exact_category_match() -> None:
    cfg = AsgionConfig(categories=frozenset({"http.fsm"}))
    assert cfg.allows(_PERF_RULE) is True  # layer="http.fsm" — exact match
    assert cfg.allows(_ERR_RULE) is False  # layer="http.scope" — not matching


def test_allows_prefix_category_match() -> None:
    cfg = AsgionConfig(categories=frozenset({"http"}))
    assert cfg.allows(_PERF_RULE) is True  # layer="http.fsm" — prefix match
    assert cfg.allows(_ERR_RULE) is True  # layer="http.scope" — prefix match
    assert cfg.allows(_WARN_RULE) is False  # layer="semantic" — no match


def test_allows_multiple_categories() -> None:
    cfg = AsgionConfig(categories=frozenset({"http.fsm", "semantic"}))
    assert cfg.allows(_PERF_RULE) is True  # "http.fsm"
    assert cfg.allows(_WARN_RULE) is True  # "semantic"
    assert cfg.allows(_ERR_RULE) is False  # "http.scope" not in categories


# AsgionConfig.allows(): include_rules allowlist


def test_allows_empty_include_rules_passes_all() -> None:
    cfg = AsgionConfig(include_rules=frozenset())
    assert cfg.allows(_PERF_RULE) is True
    assert cfg.allows(_ERR_RULE) is True


def test_allows_include_rules_allows_only_listed() -> None:
    cfg = AsgionConfig(include_rules=frozenset({"X-001"}))
    assert cfg.allows(_PERF_RULE) is True  # id="X-001" — in allowlist
    assert cfg.allows(_ERR_RULE) is False  # id="X-004" — not in allowlist


def test_allows_include_rules_applied_after_categories() -> None:
    # category matches "http.fsm", but include_rules only has X-004
    cfg = AsgionConfig(categories=frozenset({"http.fsm"}), include_rules=frozenset({"X-004"}))
    assert cfg.allows(_PERF_RULE) is False  # passes category, fails include_rules
    assert cfg.allows(_ERR_RULE) is False  # fails category (http.scope not in {http.fsm})


# AsgionConfig.allows(): include_rules glob patterns

_SEM_RULE = Rule(id="SEM-001", severity=Severity.WARNING, summary="sem rule", layer="semantic")
_SEM_PERF_RULE = Rule(
    id="SEM-006", severity=Severity.PERF, summary="sem perf rule", layer="semantic"
)
_HF_RULE = Rule(id="HF-001", severity=Severity.ERROR, summary="hf rule", layer="http.fsm")


def test_allows_include_rules_glob_prefix() -> None:
    cfg = AsgionConfig(include_rules=frozenset({"SEM-*"}))
    assert cfg.allows(_SEM_RULE) is True
    assert cfg.allows(_SEM_PERF_RULE) is True
    assert cfg.allows(_HF_RULE) is False


def test_allows_include_rules_glob_mixed_exact_and_pattern() -> None:
    cfg = AsgionConfig(include_rules=frozenset({"SEM-*", "HF-001"}))
    assert cfg.allows(_SEM_RULE) is True
    assert cfg.allows(_HF_RULE) is True
    assert cfg.allows(_PERF_RULE) is False  # X-001 — no match


def test_allows_include_rules_glob_question_mark() -> None:
    cfg = AsgionConfig(include_rules=frozenset({"SEM-00?"}))
    # SEM-001 matches SEM-00? (? = any single char)
    assert cfg.allows(_SEM_RULE) is True
    # SEM-006 also matches SEM-00?
    assert cfg.allows(_SEM_PERF_RULE) is True
    assert cfg.allows(_HF_RULE) is False


def test_allows_include_rules_exact_still_works() -> None:
    cfg = AsgionConfig(include_rules=frozenset({"SEM-001"}))
    assert cfg.allows(_SEM_RULE) is True
    assert cfg.allows(_SEM_PERF_RULE) is False  # SEM-006 — no match


# AsgionConfig.allows(): exclude_rules denylist


def test_allows_exclude_rules_suppresses_listed() -> None:
    cfg = AsgionConfig(exclude_rules=frozenset({"X-001"}))
    assert cfg.allows(_PERF_RULE) is False  # id="X-001" — in denylist
    assert cfg.allows(_ERR_RULE) is True  # id="X-004" — not in denylist


def test_allows_exclude_rules_glob() -> None:
    cfg = AsgionConfig(exclude_rules=frozenset({"X-*"}))
    assert cfg.allows(_PERF_RULE) is False  # X-001 matches X-*
    assert cfg.allows(_INFO_RULE) is False  # X-002 matches X-*
    assert cfg.allows(_SEM_RULE) is True  # SEM-001 does not match X-*


def test_allows_exclude_takes_precedence_over_include() -> None:
    cfg = AsgionConfig(
        include_rules=frozenset({"X-001"}),
        exclude_rules=frozenset({"X-001"}),
    )
    assert cfg.allows(_PERF_RULE) is False


# AsgionConfig immutability


def test_config_is_frozen() -> None:
    import dataclasses

    cfg = AsgionConfig()
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.min_severity = Severity.ERROR  # type: ignore[misc]


# BUILTIN_PROFILES


def test_builtin_profiles_exist() -> None:
    assert "strict" in BUILTIN_PROFILES
    assert "recommended" in BUILTIN_PROFILES
    assert "minimal" in BUILTIN_PROFILES


def test_profile_strict_allows_perf() -> None:
    cfg = BUILTIN_PROFILES["strict"]
    assert cfg.allows(_PERF_RULE) is True


def test_profile_recommended_blocks_perf() -> None:
    cfg = BUILTIN_PROFILES["recommended"]
    assert cfg.allows(_PERF_RULE) is False
    assert cfg.allows(_INFO_RULE) is False
    assert cfg.allows(_WARN_RULE) is True
    assert cfg.allows(_ERR_RULE) is True


def test_profile_minimal_allows_only_errors() -> None:
    cfg = BUILTIN_PROFILES["minimal"]
    assert cfg.allows(_PERF_RULE) is False
    assert cfg.allows(_INFO_RULE) is False
    assert cfg.allows(_WARN_RULE) is False
    assert cfg.allows(_ERR_RULE) is True


def test_builtin_profiles_are_independent() -> None:
    """Mutating one profile does not affect others (they're separate instances)."""
    import dataclasses

    strict = BUILTIN_PROFILES["strict"]
    modified = dataclasses.replace(strict, min_severity=Severity.ERROR)
    assert BUILTIN_PROFILES["strict"].min_severity == Severity.PERF
    assert modified.min_severity == Severity.ERROR


# _parse_config: various inputs


def test_parse_config_empty() -> None:
    cfg = _parse_config({})
    assert cfg == AsgionConfig()


def test_parse_config_profile_recommended_sets_min_severity() -> None:
    cfg = _parse_config({"profile": "recommended"})
    assert cfg.min_severity == Severity.WARNING


def test_parse_config_profile_minimal_sets_min_severity() -> None:
    cfg = _parse_config({"profile": "minimal"})
    assert cfg.min_severity == Severity.ERROR


def test_parse_config_profile_strict() -> None:
    cfg = _parse_config({"profile": "strict"})
    assert cfg.min_severity == Severity.PERF


def test_parse_config_explicit_min_severity_overrides_profile() -> None:
    """Explicit min_severity overrides the profile base."""
    cfg = _parse_config({"profile": "recommended", "min_severity": "error"})
    assert cfg.min_severity == Severity.ERROR


def test_parse_config_min_severity() -> None:
    cfg = _parse_config({"min_severity": "error"})
    assert cfg.min_severity == Severity.ERROR


def test_parse_config_exclude_rules() -> None:
    cfg = _parse_config({"exclude_rules": ["SEM-006", "G-001"]})
    assert cfg.exclude_rules == frozenset({"SEM-006", "G-001"})


def test_parse_config_include_rules() -> None:
    cfg = _parse_config({"include_rules": ["SEM-001", "SEM-002"]})
    assert cfg.include_rules == frozenset({"SEM-001", "SEM-002"})


def test_parse_config_categories() -> None:
    cfg = _parse_config({"categories": ["http.fsm", "semantic"]})
    assert cfg.categories == frozenset({"http.fsm", "semantic"})


def test_parse_config_exclude_rules_non_list_ignored() -> None:
    cfg = _parse_config({"exclude_rules": "SEM-006"})
    assert cfg.exclude_rules == frozenset()


def test_parse_config_include_rules_non_list_ignored() -> None:
    cfg = _parse_config({"include_rules": "SEM-001"})
    assert cfg.include_rules == frozenset()


def test_parse_config_categories_non_list_ignored() -> None:
    cfg = _parse_config({"categories": "http"})
    assert cfg.categories == frozenset()


def test_parse_config_thresholds() -> None:
    cfg = _parse_config(
        {
            "ttfb_threshold": 2.5,
            "lifecycle_threshold": 20.0,
            "body_size_threshold": 5242880,
            "buffer_chunk_threshold": 524288,
            "body_delivery_threshold": 8.0,
            "chunk_count_threshold": 50,
        }
    )
    assert cfg.ttfb_threshold == 2.5
    assert cfg.lifecycle_threshold == 20.0
    assert cfg.body_size_threshold == 5242880
    assert cfg.buffer_chunk_threshold == 524288
    assert cfg.body_delivery_threshold == 8.0
    assert cfg.chunk_count_threshold == 50


def test_parse_config_int_thresholds_from_int() -> None:
    cfg = _parse_config({"body_size_threshold": 1024})
    assert cfg.body_size_threshold == 1024


def test_parse_config_invalid_profile_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="'typo'"):
        _parse_config({"profile": "typo"})


def test_parse_config_invalid_min_severity_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="'extreme'"):
        _parse_config({"min_severity": "extreme"})


# load_config: explicit path


def test_load_config_explicit_asgion_toml(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    toml.write_bytes(b'profile = "minimal"\nttfb_threshold = 2.0\nexclude_rules = ["SEM-006"]\n')
    cfg = load_config(toml)
    assert cfg.min_severity == Severity.ERROR
    assert cfg.ttfb_threshold == 2.0
    assert "SEM-006" in cfg.exclude_rules


def test_load_config_explicit_pyproject_toml(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes(b'[tool.asgion]\nprofile = "strict"\nchunk_count_threshold = 50\n')
    cfg = load_config(pyproject)
    assert cfg.min_severity == Severity.PERF
    assert cfg.chunk_count_threshold == 50


def test_load_config_explicit_with_include_and_categories(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    toml.write_bytes(
        b'include_rules = ["SEM-001", "SEM-002"]\ncategories = ["http.fsm", "semantic"]\n'
    )
    cfg = load_config(toml)
    assert cfg.include_rules == frozenset({"SEM-001", "SEM-002"})
    assert cfg.categories == frozenset({"http.fsm", "semantic"})


def test_load_config_nonexistent_path_returns_defaults(tmp_path: Path) -> None:
    cfg = load_config(tmp_path / "nonexistent.toml")
    assert cfg == AsgionConfig()


def test_load_config_invalid_value_in_file_raises_config_error(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    toml.write_bytes(b'profile = "wrong"\n')
    with pytest.raises(ConfigError):
        load_config(toml)


def test_load_config_malformed_toml_raises_config_error(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    toml.write_bytes(b"this is not valid toml ][[\n")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        load_config(toml)


# load_config: auto-detection (no explicit path)


def test_load_config_auto_detects_asgion_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".asgion.toml").write_bytes(b'profile = "recommended"\n')
    cfg = load_config()
    assert cfg.min_severity == Severity.WARNING


def test_load_config_auto_detects_pyproject_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_bytes(b'[tool.asgion]\nmin_severity = "warning"\n')
    cfg = load_config()
    assert cfg.min_severity == Severity.WARNING


def test_load_config_asgion_toml_takes_priority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When both .asgion.toml and pyproject.toml exist, .asgion.toml wins."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".asgion.toml").write_bytes(b'profile = "minimal"\n')
    (tmp_path / "pyproject.toml").write_bytes(b'[tool.asgion]\nprofile = "strict"\n')
    cfg = load_config()
    assert cfg.min_severity == Severity.ERROR  # "minimal" from .asgion.toml


def test_load_config_no_files_returns_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    cfg = load_config()
    assert cfg == AsgionConfig()


def test_load_config_pyproject_without_tool_asgion_returns_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pyproject.toml without [tool.asgion] stops the search, returns defaults."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_bytes(b'[tool.pytest]\ntestpaths = ["tests"]\n')
    cfg = load_config()
    assert cfg == AsgionConfig()


# load_config: directory walking


def test_load_config_walks_up_to_find_asgion_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".asgion.toml").write_bytes(b'profile = "minimal"\n')
    subdir = tmp_path / "src" / "myapp"
    subdir.mkdir(parents=True)
    monkeypatch.chdir(subdir)
    cfg = load_config()
    assert cfg.min_severity == Severity.ERROR


def test_load_config_walks_up_to_find_pyproject_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pyproject.toml").write_bytes(b'[tool.asgion]\nprofile = "strict"\n')
    subdir = tmp_path / "tests"
    subdir.mkdir()
    monkeypatch.chdir(subdir)
    cfg = load_config()
    assert cfg.min_severity == Severity.PERF


def test_load_config_pyproject_stops_walk_even_without_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pyproject.toml (no [tool.asgion]) stops the walk — grandparent not reached."""
    grandparent = tmp_path
    (grandparent / ".asgion.toml").write_bytes(b'profile = "minimal"\n')

    parent = tmp_path / "project"
    parent.mkdir()
    (parent / "pyproject.toml").write_bytes(b'[tool.pytest]\ntestpaths = ["tests"]\n')

    subdir = parent / "src"
    subdir.mkdir()
    monkeypatch.chdir(subdir)

    cfg = load_config()
    assert cfg == AsgionConfig()


def test_load_config_closer_config_wins_over_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".asgion.toml").write_bytes(b'profile = "strict"\n')
    subdir = tmp_path / "app"
    subdir.mkdir()
    (subdir / ".asgion.toml").write_bytes(b'profile = "minimal"\n')
    monkeypatch.chdir(subdir)
    cfg = load_config()
    assert cfg.min_severity == Severity.ERROR  # "minimal" from subdir


# inspect() + config: threshold customization


async def test_inspect_with_config_custom_thresholds() -> None:
    """inspect(app, config=...) uses custom SemanticValidator thresholds."""
    cfg = AsgionConfig(body_size_threshold=100)
    violations = []

    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"x" * 200, "more_body": False})

    wrapped = inspect(app, config=cfg, on_violation=violations.append)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }

    async def receive():  # type: ignore[return]
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):  # type: ignore[no-untyped-def]
        pass

    await wrapped(scope, receive, send)
    rule_ids = [v.rule_id for v in violations]
    assert "SEM-008" in rule_ids


# inspect() + config: min_severity filtering via BUILTIN_PROFILES


async def test_inspect_recommended_profile_suppresses_perf() -> None:
    """BUILTIN_PROFILES['recommended'] suppresses PERF violations."""
    cfg = BUILTIN_PROFILES["recommended"]
    violations = []

    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    wrapped = inspect(app, config=cfg, on_violation=violations.append)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }

    async def receive():  # type: ignore[return]
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):  # type: ignore[no-untyped-def]
        pass

    await wrapped(scope, receive, send)

    from asgion.core._types import SEVERITY_LEVEL

    perf_violations = [
        v for v in violations if SEVERITY_LEVEL[v.severity] < SEVERITY_LEVEL[Severity.WARNING]
    ]
    assert perf_violations == [], f"Expected no PERF/INFO violations, got: {perf_violations}"


async def test_inspect_config_exclude_rules_merged() -> None:
    """Config.exclude_rules merged with explicit exclude_rules in inspect()."""
    cfg = AsgionConfig(exclude_rules=frozenset({"G-011"}))
    violations = []

    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    # Scope without "asgi" key to trigger G-011
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }
    wrapped = inspect(app, config=cfg, on_violation=violations.append)

    async def receive():  # type: ignore[return]
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):  # type: ignore[no-untyped-def]
        pass

    await wrapped(scope, receive, send)

    rule_ids = [v.rule_id for v in violations]
    assert "G-011" not in rule_ids
