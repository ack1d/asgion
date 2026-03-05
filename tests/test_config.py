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
    load_user_profiles,
)
from asgion.core.rule import Rule
from tests.conftest import make_asgi_scope

# Helpers

_PERF_RULE = Rule(id="X-001", severity=Severity.PERF, summary="perf rule", layer="http.fsm")
_INFO_RULE = Rule(id="X-002", severity=Severity.INFO, summary="info rule", layer="http.fsm")
_WARN_RULE = Rule(id="X-003", severity=Severity.WARNING, summary="warn rule", layer="http.semantic")
_ERR_RULE = Rule(id="X-004", severity=Severity.ERROR, summary="error rule", layer="http.scope")


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


# AsgionConfig.allows(): categories filtering


def test_allows_exact_category_match() -> None:
    cfg = AsgionConfig(categories=frozenset({"http.fsm"}))
    assert cfg.allows(_PERF_RULE) is True  # layer="http.fsm" — exact match
    assert cfg.allows(_ERR_RULE) is False  # layer="http.scope" — not matching


def test_allows_prefix_category_match() -> None:
    cfg = AsgionConfig(categories=frozenset({"http"}))
    assert cfg.allows(_PERF_RULE) is True  # layer="http.fsm" — prefix match
    assert cfg.allows(_ERR_RULE) is True  # layer="http.scope" — prefix match
    assert cfg.allows(_WARN_RULE) is True  # layer="http.semantic" — prefix match


def test_allows_multiple_categories() -> None:
    cfg = AsgionConfig(categories=frozenset({"http.fsm", "http.semantic"}))
    assert cfg.allows(_PERF_RULE) is True  # "http.fsm"
    assert cfg.allows(_WARN_RULE) is True  # "http.semantic"
    assert cfg.allows(_ERR_RULE) is False  # "http.scope" not in categories


# AsgionConfig.allows(): include_rules allowlist


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

_SEM_RULE = Rule(id="SEM-001", severity=Severity.WARNING, summary="sem rule", layer="http.semantic")
_SEM_PERF_RULE = Rule(
    id="SEM-006", severity=Severity.PERF, summary="sem perf rule", layer="http.semantic"
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


# BUILTIN_PROFILES


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


# _parse_config: various inputs


@pytest.mark.parametrize(
    ("profile", "expected_severity"),
    [
        ("recommended", Severity.WARNING),
        ("minimal", Severity.ERROR),
        ("strict", Severity.PERF),
    ],
)
def test_parse_config_profile_sets_min_severity(profile: str, expected_severity: Severity) -> None:
    cfg = _parse_config({"profile": profile})
    assert cfg.min_severity == expected_severity


def test_parse_config_explicit_min_severity_overrides_profile() -> None:
    """Explicit min_severity overrides the profile base."""
    cfg = _parse_config({"profile": "recommended", "min_severity": "error"})
    assert cfg.min_severity == Severity.ERROR


def test_parse_config_min_severity() -> None:
    cfg = _parse_config({"min_severity": "error"})
    assert cfg.min_severity == Severity.ERROR


@pytest.mark.parametrize(
    ("field", "values", "expected"),
    [
        ("exclude_rules", ["SEM-006", "G-001"], frozenset({"SEM-006", "G-001"})),
        ("include_rules", ["SEM-001", "SEM-002"], frozenset({"SEM-001", "SEM-002"})),
        ("categories", ["http.fsm", "http.semantic"], frozenset({"http.fsm", "http.semantic"})),
    ],
)
def test_parse_config_list_field(field: str, values: list[str], expected: frozenset[str]) -> None:
    cfg = _parse_config({field: values})
    assert getattr(cfg, field) == expected


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("exclude_rules", "SEM-006"),
        ("include_rules", "SEM-001"),
        ("categories", "http"),
    ],
)
def test_parse_config_non_list_ignored(field: str, bad_value: str) -> None:
    cfg = _parse_config({field: bad_value})
    assert getattr(cfg, field) == frozenset()


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
        b'include_rules = ["SEM-001", "SEM-002"]\ncategories = ["http.fsm", "http.semantic"]\n'
    )
    cfg = load_config(toml)
    assert cfg.include_rules == frozenset({"SEM-001", "SEM-002"})
    assert cfg.categories == frozenset({"http.fsm", "http.semantic"})


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
    scope = make_asgi_scope()

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
    scope = make_asgi_scope()

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


# User-defined profiles


def test_parse_config_user_defined_profile() -> None:
    data = {
        "profiles": {
            "ci": {"min_severity": "error", "categories": ["http.fsm"]},
        },
        "profile": "ci",
    }
    cfg = _parse_config(data)
    assert cfg.min_severity == Severity.ERROR
    assert cfg.categories == frozenset({"http.fsm"})


def test_parse_config_user_profile_overrides_builtin_name() -> None:
    """User can shadow a builtin profile name."""
    data = {
        "profiles": {
            "strict": {"min_severity": "error"},
        },
        "profile": "strict",
    }
    cfg = _parse_config(data)
    # User's "strict" (error) shadows builtin "strict" (perf)
    assert cfg.min_severity == Severity.ERROR


def test_parse_config_unknown_profile_with_user_profiles_raises() -> None:
    data = {
        "profiles": {"ci": {"min_severity": "error"}},
        "profile": "nope",
    }
    with pytest.raises(ConfigError, match="'nope'"):
        _parse_config(data)


def test_parse_config_user_profile_with_explicit_override() -> None:
    data = {
        "profiles": {"ci": {"min_severity": "error"}},
        "profile": "ci",
        "min_severity": "warning",
    }
    cfg = _parse_config(data)
    # Explicit min_severity overrides profile base
    assert cfg.min_severity == Severity.WARNING


def test_parse_config_profiles_key_ignored_in_profile_definition() -> None:
    """Nested profiles inside a profile definition are silently ignored."""
    data = {
        "profiles": {
            "outer": {
                "min_severity": "error",
                "profiles": {"inner": {"min_severity": "perf"}},
            },
        },
        "profile": "outer",
    }
    cfg = _parse_config(data)
    assert cfg.min_severity == Severity.ERROR


def test_parse_config_non_dict_profiles_ignored() -> None:
    data = {"profiles": "not a dict"}
    cfg = _parse_config(data)
    assert cfg == AsgionConfig()


def test_load_user_profiles_from_toml(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    toml.write_bytes(
        b'[profiles.ci]\nmin_severity = "error"\ncategories = ["http.fsm"]\n'
        b'\n[profiles.dev]\nmin_severity = "perf"\n'
    )
    profiles = load_user_profiles(toml)
    assert "ci" in profiles
    assert profiles["ci"].min_severity == Severity.ERROR
    assert profiles["ci"].categories == frozenset({"http.fsm"})
    assert "dev" in profiles
    assert profiles["dev"].min_severity == Severity.PERF


def test_load_user_profiles_from_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes(
        b'[tool.asgion.profiles.ci]\nmin_severity = "error"\n'
        b'\n[tool.asgion.profiles.dev]\nmin_severity = "warning"\n'
    )
    profiles = load_user_profiles(pyproject)
    assert "ci" in profiles
    assert profiles["ci"].min_severity == Severity.ERROR
    assert "dev" in profiles
    assert profiles["dev"].min_severity == Severity.WARNING


def test_load_user_profiles_no_profiles_returns_empty(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    toml.write_bytes(b'profile = "strict"\n')
    profiles = load_user_profiles(toml)
    assert profiles == {}


def test_load_user_profiles_nonexistent_returns_empty(tmp_path: Path) -> None:
    profiles = load_user_profiles(tmp_path / "nonexistent.toml")
    assert profiles == {}


def test_load_config_with_user_profile(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    # profile = "ci" must appear before [profiles.ci] in TOML
    toml.write_bytes(b'profile = "ci"\n\n[profiles.ci]\nmin_severity = "error"\n')
    cfg = load_config(toml)
    assert cfg.min_severity == Severity.ERROR


def test_parse_config_paths() -> None:
    cfg = _parse_config({"paths": ["/", "/api/users", "POST:/api/data", "ws:/ws/chat"]})
    assert cfg.paths == ("/", "/api/users", "POST:/api/data", "ws:/ws/chat")


def test_parse_config_paths_empty_list() -> None:
    cfg = _parse_config({"paths": []})
    assert cfg.paths == ()


def test_parse_config_paths_non_list_ignored() -> None:
    cfg = _parse_config({"paths": "/"})
    assert cfg.paths == ()


def test_load_config_paths_from_asgion_toml(tmp_path: Path) -> None:
    toml = tmp_path / ".asgion.toml"
    toml.write_bytes(b'paths = ["/", "/api/users", "POST:/api/data"]\n')
    cfg = load_config(toml)
    assert cfg.paths == ("/", "/api/users", "POST:/api/data")


def test_load_config_paths_from_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes(b'[tool.asgion]\npaths = ["/health", "ws:/ws"]\n')
    cfg = load_config(pyproject)
    assert cfg.paths == ("/health", "ws:/ws")
