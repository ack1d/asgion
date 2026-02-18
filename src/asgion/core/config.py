from __future__ import annotations

import dataclasses
import fnmatch
import functools
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from asgion.core._types import SEVERITY_LEVEL, Severity

if TYPE_CHECKING:
    from asgion.core.rule import Rule


class ConfigError(ValueError):
    """Raised when a config file contains an invalid value."""


def _is_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


@dataclass(frozen=True)
class AsgionConfig:
    """Configuration for asgion inspection.

    Can be loaded from ``.asgion.toml`` or ``pyproject.toml [tool.asgion]``
    via :func:`load_config`.

    Example ``pyproject.toml``::

        [tool.asgion]
        profile = "recommended"
        ttfb_threshold = 3.0
        exclude_rules = ["SEM-006"]
        categories = ["http.fsm", "http.semantic"]

    """

    # --- Rule filtering ---

    min_severity: Severity = Severity.PERF
    """Minimum severity to record. Rules below this are silently skipped."""

    include_rules: frozenset[str] = field(default_factory=frozenset)
    """Allowlist: if non-empty, only rules matching these patterns are active.
    Applied before ``exclude_rules``.

    Supports both exact IDs (``"SEM-001"``) and glob patterns (``"SEM-*"``).
    """

    exclude_rules: frozenset[str] = field(default_factory=frozenset)
    """Denylist: rule IDs to suppress. Applied after ``include_rules``.

    Supports both exact IDs (``"SEM-006"``) and glob patterns (``"SEM-*"``).
    """

    categories: frozenset[str] = field(default_factory=frozenset)
    """Layer prefixes to include (e.g. ``{"http"}`` or ``{"http.fsm", "http.semantic"}``).
    Empty means all categories.

    Matching uses prefix logic: ``"http"`` matches any rule whose
    ``layer`` equals ``"http"`` or starts with ``"http."``.

    Known layer values:
    - ``"general"`` — G-xxx rules
    - ``"http.scope"`` — HS-xxx scope field rules
    - ``"http.events"`` — HE-xxx event field rules
    - ``"http.fsm"`` — HF-xxx state machine rules
    - ``"http.extension"`` — EX-xxx extension rules
    - ``"http.semantic"`` — SEM-xxx semantic rules
    - ``"ws.scope"``, ``"ws.events"``, ``"ws.fsm"``
    - ``"lifespan.scope"``, ``"lifespan.events"``, ``"lifespan.fsm"``
    """

    # --- SemanticValidator thresholds ---

    ttfb_threshold: float = 5.0
    """SEM-006: TTFB threshold in seconds."""

    lifecycle_threshold: float = 30.0
    """SEM-007: Total connection lifecycle threshold in seconds."""

    body_size_threshold: int = 10 * 1024 * 1024  # 10 MB
    """SEM-008: Response body size threshold in bytes."""

    buffer_chunk_threshold: int = 1 * 1024 * 1024  # 1 MB
    """SEM-009: Single-chunk buffering threshold in bytes."""

    body_delivery_threshold: float = 10.0
    """SEM-010: Body delivery time threshold in seconds."""

    chunk_count_threshold: int = 100
    """SEM-011: Max number of body chunks before fragmentation warning."""

    # --- Pre-compiled lookups (not part of config equality or hash) ---
    #
    # Exact patterns use O(1) frozenset lookup; glob patterns use pre-compiled
    # re.Pattern objects (fnmatch.translate compiles once at construction).
    # Excluded from __eq__ / __hash__ / __repr__ — they're derived from the
    # public fields above and carry no independent information.

    _exact_include: frozenset[str] = field(
        default_factory=frozenset, init=False, compare=False, hash=False, repr=False
    )
    _glob_include: tuple[re.Pattern[str], ...] = field(
        default=(), init=False, compare=False, hash=False, repr=False
    )
    _exact_exclude: frozenset[str] = field(
        default_factory=frozenset, init=False, compare=False, hash=False, repr=False
    )
    _glob_exclude: tuple[re.Pattern[str], ...] = field(
        default=(), init=False, compare=False, hash=False, repr=False
    )

    def __post_init__(self) -> None:
        exact_inc = frozenset(p for p in self.include_rules if not _is_glob(p))
        glob_inc = tuple(
            re.compile(fnmatch.translate(p)) for p in self.include_rules if _is_glob(p)
        )
        exact_exc = frozenset(p for p in self.exclude_rules if not _is_glob(p))
        glob_exc = tuple(
            re.compile(fnmatch.translate(p)) for p in self.exclude_rules if _is_glob(p)
        )
        object.__setattr__(self, "_exact_include", exact_inc)
        object.__setattr__(self, "_glob_include", glob_inc)
        object.__setattr__(self, "_exact_exclude", exact_exc)
        object.__setattr__(self, "_glob_exclude", glob_exc)

    # AsgionConfig is frozen and long-lived (one per inspect() call),
    # so the cache is bounded by O(N_configs x N_rules) entries.
    @functools.cache  # noqa: B019
    def allows(self, rule: Rule) -> bool:
        """Return ``True`` if *rule* passes all active filters.

        Evaluation order:
        1. ``min_severity`` — rules below this level are excluded.
        2. ``categories`` — if non-empty, rule's layer must match a prefix.
        3. ``include_rules`` — if non-empty, rule ID must be in the allowlist.
        4. ``exclude_rules`` — rule ID must not be in the denylist.

        """
        if SEVERITY_LEVEL[rule.severity] < SEVERITY_LEVEL[self.min_severity]:
            return False

        if self.categories and not any(
            rule.layer == c or rule.layer.startswith(c + ".") for c in self.categories
        ):
            return False

        if self.include_rules and (
            rule.id not in self._exact_include
            and not any(p.match(rule.id) for p in self._glob_include)
        ):
            return False

        if rule.id in self._exact_exclude:
            return False

        return not any(p.match(rule.id) for p in self._glob_exclude)


# Built-in profiles — named AsgionConfig instances for common use cases.
BUILTIN_PROFILES: dict[str, AsgionConfig] = {
    "strict": AsgionConfig(),
    "recommended": AsgionConfig(min_severity=Severity.WARNING),
    "minimal": AsgionConfig(min_severity=Severity.ERROR),
}


def load_config(path: Path | str | None = None) -> AsgionConfig:
    """Load :class:`AsgionConfig` from a TOML file.

    When ``path`` is ``None``, walks up from the current directory looking for
    ``.asgion.toml`` first, then ``pyproject.toml [tool.asgion]``.  A
    ``pyproject.toml`` without a ``[tool.asgion]`` section acts as a project
    root marker and stops the search (same convention as ruff/mypy).

    Args:
        path: Explicit path to a config file (``.asgion.toml``-style or
              ``pyproject.toml``).  If ``None``, auto-detects by walking up.

    Returns:
        :class:`AsgionConfig` populated from the file, with defaults for any
        missing keys.

    Raises:
        :class:`ConfigError`: If the file contains an unrecognised value
            (e.g. ``profile = "typo"`` or ``min_severity = "extreme"``).

    """
    if path is not None:
        resolved = Path(path)
        data = _read_file(resolved) if resolved.exists() else {}
    else:
        data = _find_config()

    return _parse_config(data)


def _find_config() -> dict[str, Any]:
    """Walk up from CWD looking for a config file."""
    current = Path.cwd()
    while True:
        asgion_toml = current / ".asgion.toml"
        if asgion_toml.exists():
            return _read_file(asgion_toml)

        pyproject = current / "pyproject.toml"
        if pyproject.exists():
            # pyproject.toml marks the project root — stop here regardless of
            # whether [tool.asgion] is present, to avoid picking up a parent
            # project's config accidentally.
            return _read_file(pyproject)

        parent = current.parent
        if parent == current:  # reached filesystem root
            break
        current = parent

    return {}


def _read_file(path: Path) -> dict[str, Any]:
    """Read a TOML file and return the asgion-relevant section."""
    try:
        with path.open("rb") as f:
            raw: dict[str, Any] = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc
    if path.name == "pyproject.toml":
        tool: dict[str, Any] = raw.get("tool", {})
        section: dict[str, Any] = tool.get("asgion", {})
        return section
    return raw


def _parse_config(data: dict[str, Any]) -> AsgionConfig:
    """Parse raw key/value dict into :class:`AsgionConfig`.

    If ``profile`` is present, the corresponding :data:`BUILTIN_PROFILES`
    entry is used as the base; explicit keys in *data* override it.

    Raises:
        :class:`ConfigError`: On unrecognised enum values or unknown profiles.

    """
    if (profile_name := data.get("profile")) is not None:
        base = BUILTIN_PROFILES.get(str(profile_name))
        if base is None:
            known = ", ".join(f'"{p}"' for p in BUILTIN_PROFILES)
            raise ConfigError(f"Unknown profile {profile_name!r}. Known profiles: {known}")
    else:
        base = AsgionConfig()

    kwargs: dict[str, Any] = {}
    try:
        if (v := data.get("min_severity")) is not None:
            kwargs["min_severity"] = Severity(v)
        if (v := data.get("ttfb_threshold")) is not None:
            kwargs["ttfb_threshold"] = float(v)
        if (v := data.get("lifecycle_threshold")) is not None:
            kwargs["lifecycle_threshold"] = float(v)
        if (v := data.get("body_delivery_threshold")) is not None:
            kwargs["body_delivery_threshold"] = float(v)
        if (v := data.get("body_size_threshold")) is not None:
            kwargs["body_size_threshold"] = int(v)
        if (v := data.get("buffer_chunk_threshold")) is not None:
            kwargs["buffer_chunk_threshold"] = int(v)
        if (v := data.get("chunk_count_threshold")) is not None:
            kwargs["chunk_count_threshold"] = int(v)
    except (ValueError, TypeError) as exc:
        raise ConfigError(str(exc)) from exc

    if isinstance(rules := data.get("include_rules"), list):
        kwargs["include_rules"] = frozenset(str(r) for r in rules)
    if isinstance(rules := data.get("exclude_rules"), list):
        kwargs["exclude_rules"] = frozenset(str(r) for r in rules)
    if isinstance(cats := data.get("categories"), list):
        kwargs["categories"] = frozenset(str(c) for c in cats)

    return dataclasses.replace(base, **kwargs)
