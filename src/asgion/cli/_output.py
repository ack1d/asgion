from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from asgion import __version__
from asgion.core._types import SEVERITY_LEVEL, Severity

if TYPE_CHECKING:
    from asgion.cli._runner import CheckReport, CheckResult
    from asgion.core.rule import Rule
    from asgion.core.violation import Violation

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.ERROR: "\033[31m",  # red
    Severity.WARNING: "\033[33m",  # yellow
    Severity.INFO: "\033[36m",  # cyan
    Severity.PERF: "\033[2m",  # dim
}
_GREEN = "\033[32m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _use_color(no_color_flag: bool) -> bool:
    if no_color_flag:
        return False
    return not os.environ.get("NO_COLOR", "")


def _c(text: str, code: str, *, color: bool) -> str:
    if not color:
        return text
    return f"{code}{text}{_RESET}"


def format_text(
    report: CheckReport,
    *,
    min_severity: Severity = Severity.PERF,
    no_color: bool = False,
) -> str:
    color = _use_color(no_color)
    min_level = SEVERITY_LEVEL[min_severity]
    lines: list[str] = []
    w = lines.append

    w(f"asgion {__version__}")
    w("")
    w(f"Checking {report.app_path} ...")

    all_filtered: list[Violation] = []
    for result in report.results:
        result_violations = [
            v for v in result.violations if SEVERITY_LEVEL[v.severity] >= min_level
        ]
        all_filtered.extend(result_violations)

        label = _result_label(result)
        header = f"── {label} "
        fill = "─" * max(0, _LINE_WIDTH - len(header))
        w("")
        w(_c(header + fill, _BOLD, color=color))

        if result.error:
            w(f"  {_c('ERROR', '\033[31m', color=color)}: {result.error}")
        elif not result_violations:
            w(f"  {_c('OK', _GREEN, color=color)}")
        else:
            for v in result_violations:
                sev_color = _SEVERITY_COLORS.get(v.severity, "")
                tag = _c(f"[{v.rule_id}]", _BOLD, color=color)
                sev = _c(v.severity, sev_color, color=color)
                w(f"  {tag} {sev}: {v.message}")
                if v.hint:
                    w(f"    hint: {v.hint}")

    w("")
    w(_summary_line(all_filtered, color=color))
    return "\n".join(lines)


def _result_label(result: CheckResult) -> str:
    if result.scope_type == "lifespan":
        return "Lifespan"
    return f"{result.method} {result.path}"


def _summary_line(violations: list[Violation], *, color: bool) -> str:
    total = len(violations)
    if total == 0:
        return _c("No violations found.", _GREEN, color=color)
    by_sev: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for v in violations:
        by_sev[v.severity] += 1
    parts = [
        _c(f"{by_sev[s]} {s}", _SEVERITY_COLORS.get(s, ""), color=color)
        for s in (Severity.ERROR, Severity.WARNING, Severity.INFO, Severity.PERF)
        if by_sev[s]
    ]
    noun = "violation" if total == 1 else "violations"
    return f"{total} {noun} ({', '.join(parts)})"


def format_json(
    report: CheckReport,
    *,
    min_severity: Severity = Severity.PERF,
) -> str:
    min_level = SEVERITY_LEVEL[min_severity]
    violations = [v for v in report.all_violations if SEVERITY_LEVEL[v.severity] >= min_level]

    by_sev: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for v in violations:
        by_sev[v.severity] += 1

    data = {
        "version": __version__,
        "app": report.app_path,
        "violations": [
            {
                "rule_id": v.rule_id,
                "severity": str(v.severity),
                "message": v.message,
                "hint": v.hint,
                "scope_type": v.scope_type,
                "path": v.path,
                "method": v.method,
            }
            for v in violations
        ],
        "summary": {
            "total": len(violations),
            "error": by_sev[Severity.ERROR],
            "warning": by_sev[Severity.WARNING],
            "info": by_sev[Severity.INFO],
            "perf": by_sev[Severity.PERF],
        },
    }
    return json.dumps(data, indent=2)


_LAYER_TITLES: dict[str, str] = {
    "general": "General",
    "http.events": "HTTP Events",
    "http.fsm": "HTTP FSM",
    "ws.events": "WebSocket Events",
    "ws.fsm": "WebSocket FSM",
    "lifespan.events": "Lifespan Events",
    "lifespan.fsm": "Lifespan FSM",
}

_LAYER_ORDER: list[str] = list(_LAYER_TITLES)

_LINE_WIDTH = 66


def format_rules_text(
    rules: list[Rule],
    *,
    no_color: bool = False,
    total: int | None = None,
) -> str:
    color = _use_color(no_color)
    lines: list[str] = []
    w = lines.append

    id_w = max((len(r.id) for r in rules), default=0)
    sev_w = max((len(str(r.severity)) for r in rules), default=0)

    groups: dict[str, list[Rule]] = {}
    for r in rules:
        groups.setdefault(r.layer, []).append(r)

    count = len(rules)
    header = f"asgion {__version__} - {count} rules"
    if total is not None and total != count:
        header += f" (filtered from {total})"
    w(header)

    for layer in _LAYER_ORDER:
        group = groups.get(layer)
        if not group:
            continue

        title = _LAYER_TITLES.get(layer, layer)
        header = f"── {title} ({len(group)}) "
        fill = "─" * max(0, _LINE_WIDTH - len(header))
        w("")
        w(_c(header + fill, _BOLD, color=color))
        w("")
        for r in group:
            sev_color = _SEVERITY_COLORS.get(r.severity, "")
            rule_id = _c(r.id.ljust(id_w), _BOLD, color=color)
            severity = _c(str(r.severity).ljust(sev_w), sev_color, color=color)
            w(f"  {rule_id}  {severity}  {r.summary}")

    return "\n".join(lines)


def format_rules_json(rules: list[Rule]) -> str:
    data = {
        "version": __version__,
        "rules": [
            {
                "id": r.id,
                "severity": str(r.severity),
                "summary": r.summary,
                "hint": r.hint,
                "layer": r.layer,
                "scope_types": list(r.scope_types),
            }
            for r in rules
        ],
        "total": len(rules),
    }
    return json.dumps(data, indent=2)
