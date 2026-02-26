from __future__ import annotations

import base64
import binascii
import json
import os
from typing import TYPE_CHECKING

from asgion import __version__
from asgion.core._types import SEVERITY_LEVEL, Severity

if TYPE_CHECKING:
    from asgion.cli._runner import CheckReport, CheckResult
    from asgion.core.rule import Rule
    from asgion.core.violation import Violation
    from asgion.trace import TraceEvent, TraceRecord, TraceViolation

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.ERROR: "\033[31m",  # red
    Severity.WARNING: "\033[33m",  # yellow
    Severity.INFO: "\033[36m",  # cyan
    Severity.PERF: "\033[2m",  # dim
}
_GREEN = "\033[32m"
_BLUE = "\033[34m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_PHASE_COLORS: dict[str, str] = {
    "receive": _BLUE,
    "send": _GREEN,
}


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

    w(f"{_c('CHECK', _BOLD, color=color)}  {report.app_path}")

    all_filtered: list[Violation] = []
    first_seen: dict[tuple[str, str], str] = {}
    error_count = 0

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
            error_count += 1
            w(f"  {_c('ERROR', '\033[31m', color=color)}: {result.error}")
        elif not result_violations:
            w(f"  {_c('OK', _GREEN, color=color)}")
        else:
            for v in result_violations:
                sev_color = _SEVERITY_COLORS.get(v.severity, "")
                tag = _c(f"[{v.rule_id}]", _BOLD, color=color)
                sev = _c(v.severity, sev_color, color=color)
                key = (v.rule_id, v.message)
                if key in first_seen:
                    w(f"  {tag} {sev}: (same as {first_seen[key]})")
                else:
                    first_seen[key] = label
                    w(f"  {tag} {sev}: {v.message}")
                    if v.hint:
                        w(f"    hint: {v.hint}")

    w("")
    w(
        _summary_line(
            all_filtered,
            error_count=error_count,
            path_count=len(report.results),
            color=color,
        )
    )
    return "\n".join(lines)


def _result_label(result: CheckResult) -> str:
    if result.scope_type == "lifespan":
        return "Lifespan"
    if result.scope_type == "websocket":
        return f"WS {result.path}"
    return f"{result.method} {result.path}"


def _violations_summary(
    violations: list[Violation],
    *,
    error_count: int = 0,
    color: bool,
) -> str:
    total = len(violations)
    if total == 0 and error_count == 0:
        return _c("No violations found.", _GREEN, color=color)
    parts: list[str] = []
    if error_count > 0:
        noun = "error" if error_count == 1 else "errors"
        parts.append(_c(f"{error_count} {noun}", "\033[31m", color=color))
    if total > 0:
        by_sev: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for v in violations:
            by_sev[v.severity] += 1
        parts.extend(
            _c(f"{by_sev[s]} {s}", _SEVERITY_COLORS.get(s, ""), color=color)
            for s in (Severity.ERROR, Severity.WARNING, Severity.INFO, Severity.PERF)
            if by_sev[s]
        )
        noun = "violation" if total == 1 else "violations"
        unique = len({(v.rule_id, v.message) for v in violations})
        suffix = f" — {unique} unique" if unique < total else ""
        return f"{total} {noun} ({', '.join(parts)}){suffix}"
    return ", ".join(parts)


def _summary_line(
    violations: list[Violation],
    *,
    error_count: int = 0,
    path_count: int = 1,
    color: bool,
) -> str:
    v_part = _violations_summary(violations, error_count=error_count, color=color)
    if path_count > 1:
        return f"Scopes: {path_count}  |  {v_part}"
    return v_part


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

    groups: dict[tuple[str, str], list[Violation]] = {}
    for v in violations:
        key = (v.rule_id, v.message)
        groups.setdefault(key, []).append(v)

    deduped = []
    for vs in groups.values():
        first = vs[0]
        paths = [f"{v.method} {v.path}".strip() if (v.method or v.path) else None for v in vs]
        deduped.append(
            {
                "rule_id": first.rule_id,
                "severity": str(first.severity),
                "message": first.message,
                "hint": first.hint,
                "scope_type": first.scope_type,
                "count": len(vs),
                "paths": [p for p in paths if p],
            }
        )

    data = {
        "version": __version__,
        "app": report.app_path,
        "violations": deduped,
        "summary": {
            "total": len(violations),
            "unique": len(deduped),
            "error": by_sev[Severity.ERROR],
            "warning": by_sev[Severity.WARNING],
            "info": by_sev[Severity.INFO],
            "perf": by_sev[Severity.PERF],
        },
    }
    return json.dumps(data, indent=2)


_LAYER_TITLES: dict[str, str] = {
    "general": "General",
    "http.scope": "HTTP Scope",
    "http.events": "HTTP Events",
    "http.fsm": "HTTP FSM",
    "http.semantic": "HTTP Semantic",
    "http.extension": "HTTP Extensions",
    "ws.scope": "WebSocket Scope",
    "ws.events": "WebSocket Events",
    "ws.fsm": "WebSocket FSM",
    "lifespan.scope": "Lifespan Scope",
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
    tag = _c("RULES", _BOLD, color=color)
    counter = f"{count} / {total}" if total is not None and total != count else str(count)
    w(f"{tag}  {counter}")

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


def format_rule_detail(rule: Rule, *, no_color: bool = False) -> str:
    color = _use_color(no_color)
    sev_color = _SEVERITY_COLORS.get(rule.severity, "")
    lines: list[str] = []
    w = lines.append

    tag = _c("RULE", _BOLD, color=color)
    rule_id = _c(f"[{rule.id}]", _BOLD, color=color)
    severity = _c(str(rule.severity), sev_color, color=color)
    w(f"{tag}  {rule_id} {severity}")
    w(f"  {rule.summary}")
    if rule.hint:
        w(f"    hint: {rule.hint}")
    w("")
    w(f"  layer: {rule.layer}")
    if rule.scope_types:
        w(f"  applies to: {', '.join(rule.scope_types)}")

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


# Trace output

_RED = "\033[31m"


def _resolve_severity(rule_id: str) -> Severity | None:
    from asgion.rules import RULES

    rule = RULES.get(rule_id)
    return rule.severity if rule is not None else None


def _violation_breakdown(violations: tuple[TraceViolation, ...], *, color: bool) -> str:
    by_sev: dict[Severity, int] = {}
    for v in violations:
        sev = _resolve_severity(v.rule_id)
        if sev is not None:
            by_sev[sev] = by_sev.get(sev, 0) + 1
    if not by_sev:
        return ""
    return ", ".join(
        _c(f"{by_sev[s]} {s}", _SEVERITY_COLORS.get(s, ""), color=color)
        for s in (Severity.ERROR, Severity.WARNING, Severity.INFO, Severity.PERF)
        if by_sev.get(s)
    )


def _ns_to_ms(ns: int) -> str:
    return f"{ns / 1_000_000:.3f}ms"


def _b64_byte_count(b64: str) -> int:
    try:
        return len(base64.b64decode(b64))
    except (ValueError, binascii.Error):
        return 0


def _event_highlights(event: TraceEvent) -> str:
    etype = event.type
    data = event.data

    if etype == "http.response.start":
        parts: list[str] = []
        status = data.get("status")
        if status is not None:
            parts.append(str(status))
        headers = data.get("headers", [])
        for name, value in headers:
            if name == "content-type":
                parts.append(value)
                break
        return " ".join(parts) if parts else ""
    if etype in ("http.response.body", "http.request"):
        body = data.get("body", "")
        if body:
            n = _b64_byte_count(body)
            return f"{n} bytes"
    elif etype == "websocket.accept":
        sub = data.get("subprotocol")
        if sub:
            return f"subprotocol={sub}"
    elif etype in ("websocket.send", "websocket.receive"):
        text = data.get("text")
        if text is not None:
            preview = text[:40] + ("..." if len(text) > 40 else "")
            return f'"{preview}"'
        b = data.get("bytes", "")
        if b:
            n = _b64_byte_count(b)
            return f"{n} bytes"
    return ""


def _max_violation_severity(violation_ids: list[str]) -> Severity | None:
    max_level = -1
    max_sev: Severity | None = None
    for vid in violation_ids:
        sev = _resolve_severity(vid)
        if sev is not None:
            level = SEVERITY_LEVEL[sev]
            if level > max_level:
                max_level = level
                max_sev = sev
    return max_sev


def _format_event_line(
    event: TraceEvent,
    *,
    prev_ns: int | None,
    color: bool,
    violation_ids: list[str] | None = None,
) -> str:
    t = _ns_to_ms(event.t_ns).rjust(10)
    phase_color = _PHASE_COLORS.get(event.phase, _DIM)
    phase = _c(event.phase.ljust(7), phase_color, color=color)
    etype = event.type
    if violation_ids:
        max_sev = _max_violation_severity(violation_ids)
        etype_color = _SEVERITY_COLORS.get(max_sev, _RED) if max_sev else _RED
        etype = _c(etype, etype_color, color=color)
    highlights = _event_highlights(event)
    suffix = f"  {highlights}" if highlights else ""
    delta = ""
    if prev_ns is not None:
        delta_ns = event.t_ns - prev_ns
        delta = "  " + _c(f"(+{_ns_to_ms(delta_ns)})", _DIM, color=color)
    marker = ""
    if violation_ids:
        parts = []
        for vid in violation_ids:
            sev = _resolve_severity(vid)
            sev_color = _SEVERITY_COLORS.get(sev, _RED) if sev else _RED
            label = f"{vid} ({sev})" if sev is not None else vid
            parts.append(_c(label, sev_color, color=color))
        marker = "  " + _c("\u2190 ", _DIM, color=color) + ", ".join(parts)
    return f"  {t}  {phase}  {etype}{suffix}{delta}{marker}"


def _trace_header(record: TraceRecord, *, color: bool) -> str:
    scope = record.scope
    summary = record.summary
    duration = _ns_to_ms(summary.total_ns)

    if scope.type == "lifespan":
        label = "lifespan"
    elif scope.type == "websocket":
        label = f"WS {scope.path}" if scope.path else "WS"
    else:
        method = scope.method or "?"
        path = scope.path or "/"
        label = f"{method} {path}"

    timing = duration
    if summary.ttfb_ns is not None:
        timing += f", TTFB {_ns_to_ms(summary.ttfb_ns)}"

    tag = _c("TRACE", _BOLD, color=color)
    return f"{tag}  {label} ({timing})"


def _build_violation_indexes(
    violations: tuple[TraceViolation, ...],
) -> tuple[list[str], dict[int, list[str]], list[str]]:
    scope_ids: list[str] = []
    by_event: dict[int, list[str]] = {}
    complete_ids: list[str] = []
    for v in violations:
        if v.phase == "scope":
            scope_ids.append(v.rule_id)
        elif v.phase == "complete":
            complete_ids.append(v.rule_id)
        elif v.event_index is not None:
            by_event.setdefault(v.event_index, []).append(v.rule_id)
    return scope_ids, by_event, complete_ids


def _filter_trace_violations(
    violations: tuple[TraceViolation, ...],
    min_severity: Severity,
) -> tuple[TraceViolation, ...]:
    if min_severity == Severity.PERF:
        return violations
    min_level = SEVERITY_LEVEL[min_severity]
    return tuple(
        v
        for v in violations
        if (sev := _resolve_severity(v.rule_id)) is not None and SEVERITY_LEVEL[sev] >= min_level
    )


def format_trace_text(
    records: list[TraceRecord],
    *,
    app_path: str = "",
    no_color: bool = False,
    min_severity: Severity = Severity.PERF,
) -> str:
    """Format trace records as human-readable text."""
    color = _use_color(no_color)
    parts: list[str] = []

    for i, record in enumerate(records):
        if i > 0:
            parts.append(_c("─" * _LINE_WIDTH, _DIM, color=color))
            parts.append("")

        parts.append(_trace_header(record, color=color))
        parts.append("")

        filtered_violations = _filter_trace_violations(
            record.summary.violations,
            min_severity,
        )
        scope_ids, by_event, complete_ids = _build_violation_indexes(filtered_violations)

        if scope_ids:
            label = _c(", ".join(scope_ids), _RED, color=color)
            parts.append(f"  scope: {label}")
            parts.append("")

        prev_ns: int | None = None
        for idx, event in enumerate(record.events):
            v_ids = by_event.get(idx)
            parts.append(
                _format_event_line(event, prev_ns=prev_ns, color=color, violation_ids=v_ids)
            )
            prev_ns = event.t_ns

        if complete_ids:
            parts.append("")
            label = _c(", ".join(complete_ids), _RED, color=color)
            parts.append(f"  complete: {label}")

        parts.append("")

        v_count = len(filtered_violations)
        e_count = record.summary.event_count
        footer = f"  Events: {e_count}  |  Violations: "
        if v_count > 0:
            footer += _c(str(v_count), _RED, color=color)
            breakdown = _violation_breakdown(filtered_violations, color=color)
            if breakdown:
                footer += f" ({breakdown})"
        else:
            footer += _c("0", _GREEN, color=color)
        parts.append(footer)

    if len(records) > 1:
        total_ns = sum(r.summary.total_ns for r in records)
        total_events = sum(r.summary.event_count for r in records)
        all_violations = _filter_trace_violations(
            tuple(v for r in records for v in r.summary.violations),
            min_severity,
        )
        segments = [
            f"{len(records)} traces",
            f"{total_events} events",
        ]
        if all_violations:
            label = f"{len(all_violations)} violations"
            breakdown = _violation_breakdown(all_violations, color=color)
            if breakdown:
                label += f" ({breakdown})"
            segments.append(_c(label, _RED, color=color))
        segments.append(_ns_to_ms(total_ns))
        parts.append("")
        prefix = f"{app_path} | " if app_path else ""
        parts.append(_c("─", _DIM, color=color) + " " + prefix + " | ".join(segments))

    return "\n".join(parts)


def format_trace_json(records: list[TraceRecord]) -> str:
    """Format trace records as JSON (one object per record, newline-separated)."""
    from asgion.trace._format import serialize

    return "\n".join(serialize(r) for r in records)
