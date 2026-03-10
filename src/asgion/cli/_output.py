from __future__ import annotations

import base64
import binascii
import json
import os
import xml.etree.ElementTree as ET
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
    return "NO_COLOR" not in os.environ


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
            elapsed_s=report.elapsed_s,
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


def _fmt_duration(s: float) -> str:
    if s < 0.001:
        return f"{s * 1_000_000:.0f}\u00b5s"
    if s < 1:
        return f"{s * 1000:.1f}ms"
    if s < 60:
        return f"{s:.2f}s"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{int(m)}m{sec:.0f}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h{int(m)}m{sec:.0f}s"


def _summary_line(
    violations: list[Violation],
    *,
    error_count: int = 0,
    path_count: int = 1,
    elapsed_s: float = 0.0,
    color: bool,
) -> str:
    v_part = _violations_summary(violations, error_count=error_count, color=color)
    parts: list[str] = []
    if path_count > 1:
        parts.append(f"Scopes: {path_count}")
    parts.append(v_part)
    if elapsed_s > 0:
        parts.append(_c(_fmt_duration(elapsed_s), _DIM, color=color))
    return "  |  ".join(parts)


_GITHUB_LEVEL: dict[Severity, str] = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "notice",
    Severity.PERF: "notice",
}


def format_github(
    report: CheckReport,
    *,
    min_severity: Severity = Severity.PERF,
) -> str:
    """Format as GitHub Actions workflow commands (``::error::``, etc.)."""
    min_level = SEVERITY_LEVEL[min_severity]
    lines: list[str] = []
    for result in report.results:
        label = _result_label(result)
        for v in result.violations:
            if SEVERITY_LEVEL[v.severity] < min_level:
                continue
            level = _GITHUB_LEVEL[v.severity]
            title = f"[{v.rule_id}] {v.severity}"
            msg = f"{v.message} ({label})"
            lines.append(f"::{level} title={title}::{msg}")
    return "\n".join(lines)


_SARIF_LEVEL: dict[Severity, str] = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
    Severity.PERF: "note",
}


def format_sarif(
    report: CheckReport,
    *,
    min_severity: Severity = Severity.PERF,
) -> str:
    from asgion.rules import RULES

    min_level = SEVERITY_LEVEL[min_severity]
    results_json: list[dict[str, object]] = []
    seen_rule_ids: dict[str, Rule] = {}

    for result in report.results:
        label = _result_label(result)
        for v in result.violations:
            if SEVERITY_LEVEL[v.severity] < min_level:
                continue
            rule = RULES.get(v.rule_id)
            if rule is not None:
                seen_rule_ids[v.rule_id] = rule
            sarif_result: dict[str, object] = {
                "ruleId": v.rule_id,
                "level": _SARIF_LEVEL.get(v.severity, "note"),
                "message": {"text": v.message},
                "locations": [
                    {
                        "logicalLocation": {
                            "name": label,
                            "kind": "scope",
                        }
                    }
                ],
            }
            if v.hint:
                sarif_result["properties"] = {"hint": v.hint}
            results_json.append(sarif_result)

    rules_json: list[dict[str, object]] = []
    for rule_id, rule in seen_rule_ids.items():
        rule_entry: dict[str, object] = {
            "id": rule_id,
            "shortDescription": {"text": rule.summary},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(rule.severity, "note")},
        }
        tags = ["asgi"]
        if rule.layer:
            tags.append(rule.layer)
        tags.extend(sorted(rule.tags))
        rule_entry["properties"] = {"tags": tags}
        rules_json.append(rule_entry)

    sarif: dict[str, object] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "asgion",
                        "version": __version__,
                        "informationUri": "https://github.com/ack1d/asgion",
                        "rules": rules_json,
                    }
                },
                "results": results_json,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_junit(
    report: CheckReport,
    *,
    min_severity: Severity = Severity.PERF,
) -> str:
    min_level = SEVERITY_LEVEL[min_severity]

    testsuites = ET.Element("testsuites")
    testsuite = ET.SubElement(testsuites, "testsuite")
    testsuite.set("name", "asgion")
    testsuite.set("timestamp", "")

    total_tests = 0
    total_failures = 0
    total_errors = 0

    for result in report.results:
        label = _result_label(result)
        tc = ET.SubElement(testsuite, "testcase")
        tc.set("name", label)
        tc.set("classname", report.app_path)
        total_tests += 1

        if result.error:
            total_errors += 1
            err = ET.SubElement(tc, "error")
            err.set("message", result.error)
            continue

        filtered = [v for v in result.violations if SEVERITY_LEVEL[v.severity] >= min_level]
        if filtered:
            total_failures += 1
            lines: list[str] = []
            for v in filtered:
                line = f"[{v.rule_id}] {v.severity}: {v.message}"
                if v.hint:
                    line += f"\n  hint: {v.hint}"
                lines.append(line)
            failure = ET.SubElement(tc, "failure")
            failure.set("message", f"{len(filtered)} violation(s)")
            failure.set("type", "violation")
            failure.text = "\n\n".join(lines)

    testsuite.set("tests", str(total_tests))
    testsuite.set("failures", str(total_failures))
    testsuite.set("errors", str(total_errors))
    testsuite.set("time", f"{report.elapsed_s:.3f}")

    ET.indent(testsuites)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(testsuites, encoding="unicode")


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
    w(f"  layer:      {rule.layer}")
    if rule.scope_types:
        w(f"  applies to: {', '.join(rule.scope_types)}")
    if rule.tags:
        w(f"  tags:       {', '.join(sorted(rule.tags))}")
    if rule.deprecated:
        w(f"  {_c('deprecated', _DIM, color=color)}")
    w("")
    w(f'  suppress: exclude_rules = ["{rule.id}"]')

    return "\n".join(lines)


def format_rules_json(rules: list[Rule], *, total: int | None = None) -> str:
    data: dict[str, object] = {
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
    if total is not None:
        data["total_available"] = total
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


def _fmt_ns(ns: int) -> str:
    return _fmt_duration(ns / 1_000_000_000)


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
    t = _fmt_ns(event.t_ns).rjust(10)
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
        delta = "  " + _c(f"(+{_fmt_ns(delta_ns)})", _DIM, color=color)
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
    duration = _fmt_ns(summary.total_ns)

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
        timing += f", TTFB {_fmt_ns(summary.ttfb_ns)}"

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
        segments.append(_fmt_ns(total_ns))
        parts.append("")
        prefix = f"{app_path} | " if app_path else ""
        parts.append(_c("─", _DIM, color=color) + " " + prefix + " | ".join(segments))

    return "\n".join(parts)


def format_trace_json(records: list[TraceRecord]) -> str:
    """Format trace records as JSON (one object per record, newline-separated)."""
    from asgion.trace._format import serialize

    return "\n".join(serialize(r) for r in records)
