import json
import xml.etree.ElementTree as ET

import pytest
from click.testing import CliRunner

from asgion.cli._driver import parse_path
from asgion.cli._loader import LoadError, load_app
from asgion.cli._output import (
    _fmt_duration,
    format_json,
    format_junit,
    format_rules_json,
    format_rules_text,
    format_sarif,
    format_text,
)
from asgion.cli._runner import CheckReport, CheckResult, run_check
from asgion.cli.main import cli
from asgion.core._types import Severity
from asgion.core.violation import Violation
from asgion.rules import ALL_RULES


class TestLoader:
    def test_no_colon(self) -> None:
        with pytest.raises(LoadError, match="expected 'module:attribute'"):
            load_app("myapp")

    def test_import_error(self) -> None:
        with pytest.raises(LoadError, match="Could not import"):
            load_app("nonexistent_module_xyz:app")

    def test_attribute_error(self) -> None:
        with pytest.raises(LoadError, match="has no attribute"):
            load_app("tests._cli_fixtures:no_such_attr")

    def test_not_callable(self) -> None:
        with pytest.raises(LoadError, match="not callable"):
            load_app("tests._cli_fixtures:not_callable")

    def test_success(self) -> None:
        app = load_app("tests._cli_fixtures:good_app")
        assert callable(app)


class TestRunner:
    def test_good_app_no_violations(self) -> None:
        from tests._cli_fixtures import good_lifespan_app

        report = run_check(good_lifespan_app, app_path="test:app", run_lifespan=True)
        assert report.all_violations == []

    def test_bad_app_has_violations(self) -> None:
        from tests._cli_fixtures import bad_app

        report = run_check(bad_app, app_path="test:app", run_lifespan=False)
        assert len(report.all_violations) > 0

    def test_multiple_urls(self) -> None:
        from tests._cli_fixtures import good_lifespan_app

        report = run_check(
            good_lifespan_app,
            app_path="test:app",
            paths=("/", "/other"),
            run_lifespan=False,
        )
        assert len(report.results) == 2

    def test_no_lifespan(self) -> None:
        from tests._cli_fixtures import good_lifespan_app

        report = run_check(good_lifespan_app, app_path="test:app", run_lifespan=False)
        assert all(r.scope_type == "http" for r in report.results)

    def test_ws_path_no_violations(self) -> None:
        from tests._cli_fixtures import good_ws_app

        report = run_check(good_ws_app, app_path="test:app", paths=("ws:/ws",), run_lifespan=False)
        assert len(report.results) == 1
        assert report.results[0].scope_type == "websocket"
        assert report.all_violations == []

    def test_ws_path_label_in_text_output(self) -> None:
        from asgion.cli._output import format_text
        from tests._cli_fixtures import good_ws_app

        report = run_check(
            good_ws_app, app_path="test:app", paths=("ws:/ws/chat",), run_lifespan=False
        )
        text = format_text(report, no_color=True)
        assert "WS /ws/chat" in text

    def test_filtered(self) -> None:
        v1 = Violation(rule_id="X-001", severity=Severity.INFO, message="info")
        v2 = Violation(rule_id="X-002", severity=Severity.ERROR, message="err")
        report = CheckReport(app_path="t:a", results=[CheckResult("http", violations=[v1, v2])])
        assert len(report.filtered(Severity.ERROR)) == 1
        assert len(report.filtered(Severity.INFO)) == 2


class TestOutput:
    def _make_report(self, *, violations: list[Violation] | None = None) -> CheckReport:
        vv = violations or []
        return CheckReport(
            app_path="myapp:app",
            results=[CheckResult("http", path="/", method="GET", violations=vv)],
        )

    def test_text_no_violations(self) -> None:
        text = format_text(self._make_report(), no_color=True)
        assert "No violations found." in text
        assert "myapp:app" in text

    def test_text_with_violations(self) -> None:
        v = Violation(
            rule_id="HE-007",
            severity=Severity.WARNING,
            message="Unusual status",
            hint="Check status code",
        )
        text = format_text(self._make_report(violations=[v]), no_color=True)
        assert "HE-007" in text
        assert "warning" in text
        assert "hint: Check status code" in text
        assert "1 violation" in text

    def test_json_output(self) -> None:
        v = Violation(rule_id="G-001", severity=Severity.ERROR, message="bad scope")
        out = format_json(self._make_report(violations=[v]))
        data = json.loads(out)
        assert data["summary"]["total"] == 1
        assert data["summary"]["unique"] == 1
        assert data["summary"]["error"] == 1
        assert data["violations"][0]["rule_id"] == "G-001"
        assert data["violations"][0]["count"] == 1

    def test_json_min_severity(self) -> None:
        v1 = Violation(rule_id="X-001", severity=Severity.PERF, message="perf")
        v2 = Violation(rule_id="X-002", severity=Severity.ERROR, message="err")
        out = format_json(self._make_report(violations=[v1, v2]), min_severity=Severity.ERROR)
        data = json.loads(out)
        assert data["summary"]["total"] == 1

    def _make_multi_url_report(self, violation: Violation) -> CheckReport:
        """Two URL results with the same violation."""
        return CheckReport(
            app_path="myapp:app",
            results=[
                CheckResult("http", path="/a", method="GET", violations=[violation]),
                CheckResult("http", path="/b", method="GET", violations=[violation]),
            ],
        )

    def test_text_dedup_same_as_reference(self) -> None:
        v = Violation(rule_id="HF-001", severity=Severity.ERROR, message="No response sent")
        text = format_text(self._make_multi_url_report(v), no_color=True)
        # violation shown fully in first section
        assert "HF-001" in text
        # second occurrence references the first
        assert "same as GET /a" in text
        # summary shows dedup info
        assert "1 unique" in text

    def test_text_dedup_different_messages_not_grouped(self) -> None:
        v1 = Violation(rule_id="HF-001", severity=Severity.ERROR, message="msg A")
        v2 = Violation(rule_id="HF-001", severity=Severity.ERROR, message="msg B")
        report = CheckReport(
            app_path="myapp:app",
            results=[
                CheckResult("http", path="/a", method="GET", violations=[v1]),
                CheckResult("http", path="/b", method="GET", violations=[v2]),
            ],
        )
        text = format_text(report, no_color=True)
        # Different messages — both shown fully, no dedup
        assert "msg A" in text
        assert "msg B" in text
        assert "same as" not in text

    def test_json_dedup_count_and_paths(self) -> None:
        v = Violation(
            rule_id="HF-001",
            severity=Severity.ERROR,
            message="No response sent",
            path="/a",
            method="GET",
        )
        v2 = Violation(
            rule_id="HF-001",
            severity=Severity.ERROR,
            message="No response sent",
            path="/b",
            method="GET",
        )
        report = CheckReport(
            app_path="myapp:app",
            results=[
                CheckResult("http", path="/a", method="GET", violations=[v]),
                CheckResult("http", path="/b", method="GET", violations=[v2]),
            ],
        )
        data = json.loads(format_json(report))
        assert data["summary"]["total"] == 2
        assert data["summary"]["unique"] == 1
        assert len(data["violations"]) == 1
        entry = data["violations"][0]
        assert entry["count"] == 2
        assert "GET /a" in entry["paths"]
        assert "GET /b" in entry["paths"]

    def test_rules_text(self) -> None:
        text = format_rules_text(ALL_RULES, no_color=True)
        assert str(len(ALL_RULES)) in text
        assert "G-001" in text

    def test_rules_json(self) -> None:
        out = format_rules_json(ALL_RULES)
        data = json.loads(out)
        assert data["total"] == len(ALL_RULES)
        assert data["rules"][0]["id"]


class TestCLI:
    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "asgion" in result.output

    def test_rules_text(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "--no-color"])
        assert result.exit_code == 0
        assert str(len(ALL_RULES)) in result.output

    def test_rules_json(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == len(ALL_RULES)

    def test_check_good_app(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:good_lifespan_app", "--no-color", "--no-lifespan"],
        )
        assert result.exit_code == 0
        assert "No violations found." in result.output

    def test_check_bad_app(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:bad_app", "--no-color", "--no-lifespan"],
        )
        assert result.exit_code == 0
        assert "violation" in result.output.lower()

    def test_check_strict_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:bad_app", "--strict", "--no-lifespan"],
        )
        assert result.exit_code == 1

    def test_check_json_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:bad_app", "--format", "json", "--no-lifespan"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["total"] > 0

    def test_check_exclude_rules(self) -> None:
        runner = CliRunner()
        result1 = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:bad_app", "--format", "json", "--no-lifespan"],
        )
        data1 = json.loads(result1.output)
        rule_ids = {v["rule_id"] for v in data1["violations"]}
        assert rule_ids, "bad_app should produce violations"

        exclusion = ",".join(rule_ids)
        result2 = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:bad_app",
                "--format",
                "json",
                "--no-lifespan",
                "--exclude-rules",
                exclusion,
            ],
        )
        assert result2.exit_code == 0
        data2 = json.loads(result2.output)
        assert data2["summary"]["total"] == 0

    def test_check_min_severity(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:bad_app",
                "--format",
                "json",
                "--no-lifespan",
                "--min-severity",
                "error",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        for v in data["violations"]:
            assert v["severity"] == "error"

    def test_bad_module_path_exits_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "nonexistent:app"])
        assert result.exit_code == 2

    def test_missing_colon_exits_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "nomodule"])
        assert result.exit_code == 2

    def test_rules_layer_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "--no-color", "--layer", "http"])
        assert result.exit_code == 0
        assert f"/ {len(ALL_RULES)}" in result.output
        for line in result.output.splitlines():
            if line.startswith("  ") and line[2:].strip() and line[2:].strip()[0].isalpha():
                rule_id = line.split()[0]
                assert rule_id.startswith(("HE-", "HF-", "HS-", "EX-", "SEM-")), rule_id

    def test_rules_severity_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "--no-color", "--severity", "warning"])
        assert result.exit_code == 0
        assert f"/ {len(ALL_RULES)}" in result.output
        assert "warning" in result.output
        assert "  error  " not in result.output

    def test_rules_layer_and_severity_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["rules", "--format", "json", "--layer", "http", "--severity", "error"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        for r in data["rules"]:
            assert r["layer"].startswith("http.")
            assert r["severity"] == "error"

    def test_rules_text_total_param(self) -> None:
        total = len(ALL_RULES)
        text = format_rules_text(ALL_RULES[:5], no_color=True, total=total)
        assert f"5 / {total}" in text

    @pytest.mark.parametrize(
        ("prefix_path", "app", "expected_label"),
        [
            ("ws:/ws", "good_ws_app", "WS /ws"),
            ("wss:/ws", "good_ws_app", "WS /ws"),
            ("http:/api", "good_lifespan_app", "GET /api"),
        ],
    )
    def test_check_protocol_prefix(self, prefix_path: str, app: str, expected_label: str) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                f"tests._cli_fixtures:{app}",
                "--no-color",
                "--no-lifespan",
                "--path",
                prefix_path,
            ],
        )
        assert result.exit_code == 0
        assert expected_label in result.output

    def test_check_mixed_paths(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_ws_app",
                "--no-color",
                "--no-lifespan",
                "--path",
                "/",
                "--path",
                "ws:/ws",
            ],
        )
        assert result.exit_code == 0
        assert "GET /" in result.output
        assert "WS /ws" in result.output

    def test_check_with_lifespan(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--no-color",
            ],
        )
        assert result.exit_code == 0
        assert "Lifespan" in result.output

    def test_check_builtin_profile(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--profile",
                "strict",
                "--no-lifespan",
                "--no-color",
            ],
        )
        assert result.exit_code == 0

    def test_check_unknown_profile_exits_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--profile",
                "nonexistent_profile_xyz",
                "--no-lifespan",
            ],
        )
        assert result.exit_code == 2
        assert "unknown profile" in result.output.lower()

    def test_rules_single_lookup(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "HF-001", "--no-color"])
        assert result.exit_code == 0
        assert "RULE" in result.output
        assert "[HF-001]" in result.output
        assert "error" in result.output
        assert "layer: http.fsm" in result.output

    def test_rules_single_lookup_json(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "HF-001", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["rules"]) == 1
        assert data["rules"][0]["id"] == "HF-001"

    def test_rules_unknown_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "NOPE-999"])
        assert result.exit_code == 2
        assert "Error: unknown rule: NOPE-999" in result.output

    def test_rules_single_ignores_filters(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "HF-001", "--layer", "ws", "--no-color"])
        assert result.exit_code == 0
        assert "HF-001" in result.output

    def test_check_help_exit_codes(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--help"])
        assert result.exit_code == 0
        assert "Exit codes:" in result.output
        assert "0  success" in result.output
        assert "1  violations found" in result.output
        assert "2  runtime error" in result.output

    def test_check_scopes_label(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--no-color",
                "--path",
                "/",
                "--path",
                "/other",
            ],
        )
        assert result.exit_code == 0
        assert "Scopes:" in result.output
        assert "Paths:" not in result.output

    def test_trace_min_severity_text(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "trace",
                "tests._cli_fixtures:bad_app",
                "--no-color",
                "--min-severity",
                "error",
            ],
        )
        assert result.exit_code == 0
        # With error filter, info/warning markers should not appear
        for line in result.output.splitlines():
            if "\u2190" in line:
                assert "error" in line.lower()

    def test_trace_min_severity_default(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "trace",
                "tests._cli_fixtures:bad_app",
                "--no-color",
            ],
        )
        assert result.exit_code == 0
        assert "Violations:" in result.output

    def test_check_user_defined_profile(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        config = tmp_path / ".asgion.toml"
        config.write_bytes(b'[profiles.ci]\nmin_severity = "error"\n')
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:bad_app",
                "--profile",
                "ci",
                "--config",
                str(config),
                "--no-lifespan",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        for v in data["violations"]:
            assert v["severity"] == "error"

    def test_check_strict_min_severity_no_exit(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:warn_only_app",
                "--strict",
                "--min-severity",
                "error",
                "--no-lifespan",
            ],
        )
        assert result.exit_code == 0

    def test_check_raising_app_text(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:raising_app", "--no-color", "--no-lifespan"],
        )
        assert result.exit_code == 0
        assert "ERROR" in result.output

    def test_check_raising_app_strict(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:raising_app", "--strict", "--no-lifespan"],
        )
        assert result.exit_code == 1

    def test_trace_out_directory(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "trace",
                "tests._cli_fixtures:good_lifespan_app",
                "--out",
                str(tmp_path),
                "--no-lifespan",
            ],
        )
        assert result.exit_code == 0
        files = list(tmp_path.glob("*.json"))
        assert len(files) > 0

    def test_trace_format_json(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "trace",
                "tests._cli_fixtures:good_lifespan_app",
                "--format",
                "json",
                "--no-lifespan",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "scope" in data

    def test_check_invalid_config_exits_2(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        config = tmp_path / ".asgion.toml"
        config.write_text("not valid [[[toml")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_app",
                "--config",
                str(config),
                "--no-lifespan",
            ],
        )
        assert result.exit_code == 2
        assert "Error" in result.output

    def test_trace_bad_module_exits_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["trace", "nonexistent_module_xyz:app"])
        assert result.exit_code == 2
        assert "Error" in result.output

    def test_no_color_env_empty(self) -> None:
        runner = CliRunner(env={"NO_COLOR": ""})
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:good_lifespan_app", "--no-lifespan"],
        )
        assert result.exit_code == 0
        assert "\033[" not in result.output

    def test_check_raising_app_summary(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:raising_app", "--no-color", "--no-lifespan"],
        )
        assert result.exit_code == 0
        assert "1 error" in result.output

    def test_check_exclude_rules_glob(self) -> None:
        runner = CliRunner()
        # First get violations
        result1 = runner.invoke(
            cli,
            ["check", "tests._cli_fixtures:bad_app", "--format", "json", "--no-lifespan"],
        )
        data1 = json.loads(result1.output)
        assert data1["summary"]["total"] > 0

        # Exclude all rules via glob
        result2 = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:bad_app",
                "--format",
                "json",
                "--no-lifespan",
                "--exclude-rules",
                "*",
            ],
        )
        assert result2.exit_code == 0
        data2 = json.loads(result2.output)
        assert data2["summary"]["total"] == 0

    def test_rules_json_total_available(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "--format", "json", "--layer", "http"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "total_available" in data
        assert data["total_available"] == len(ALL_RULES)

    def test_check_config_paths_used_when_no_cli_path(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        config = tmp_path / ".asgion.toml"
        config.write_bytes(b'paths = ["/", "/other"]\n')
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--config",
                str(config),
                "--no-lifespan",
                "--no-color",
            ],
        )
        assert result.exit_code == 0
        assert "GET /" in result.output
        assert "GET /other" in result.output

    def test_check_cli_path_overrides_config_paths(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        config = tmp_path / ".asgion.toml"
        config.write_bytes(b'paths = ["/", "/other"]\n')
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--config",
                str(config),
                "--path",
                "/only-this",
                "--no-lifespan",
                "--no-color",
            ],
        )
        assert result.exit_code == 0
        assert "GET /only-this" in result.output
        assert "GET /other" not in result.output

    def test_trace_strict_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["trace", "tests._cli_fixtures:bad_app", "--strict", "--no-lifespan"],
        )
        assert result.exit_code == 1

    def test_trace_strict_clean_exits_0(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["trace", "tests._cli_fixtures:good_app", "--strict", "--no-lifespan"],
        )
        assert result.exit_code == 0

    def test_trace_strict_min_severity_filters(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "trace",
                "tests._cli_fixtures:warn_only_app",
                "--strict",
                "--min-severity",
                "error",
                "--no-lifespan",
            ],
        )
        assert result.exit_code == 0

    def test_check_no_path_no_config_defaults_to_root(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--no-lifespan",
                "--no-color",
            ],
        )
        assert result.exit_code == 0
        assert "GET /" in result.output


class TestParsePath:
    def test_plain_path(self) -> None:
        assert parse_path("/api") == ("http", "/api", "GET")

    def test_method_prefix_post(self) -> None:
        assert parse_path("POST:/api") == ("http", "/api", "POST")

    def test_method_prefix_delete(self) -> None:
        assert parse_path("DELETE:/api/1") == ("http", "/api/1", "DELETE")

    def test_default_method_override(self) -> None:
        assert parse_path("/api", default_method="POST") == ("http", "/api", "POST")


class TestTimeout:
    def test_hanging_app_times_out(self) -> None:
        async def hanging_app(scope, receive, send):  # type: ignore[no-untyped-def]
            if scope["type"] == "http":
                import asyncio

                await asyncio.sleep(999)

        report = run_check(
            hanging_app,
            app_path="test:app",
            run_lifespan=False,
            scope_timeout=0.1,
        )
        assert len(report.results) == 1


class TestFmtDuration:
    def test_seconds(self) -> None:
        assert _fmt_duration(5.0) == "5.00s"

    def test_minutes(self) -> None:
        assert _fmt_duration(90.0) == "1m30s"

    def test_hours(self) -> None:
        assert _fmt_duration(3661.0) == "1h1m1s"


class TestFormatSarif:
    def _make_report(self, *, violations: list[Violation] | None = None) -> CheckReport:
        vv = violations or []
        return CheckReport(
            app_path="myapp:app",
            results=[CheckResult("http", path="/", method="GET", violations=vv)],
        )

    def test_sarif_empty(self) -> None:
        out = format_sarif(self._make_report())
        data = json.loads(out)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"] == []

    def test_sarif_with_violation(self) -> None:
        v = Violation(
            rule_id="HE-007",
            severity=Severity.WARNING,
            message="Unusual status",
            hint="Check status code",
        )
        out = format_sarif(self._make_report(violations=[v]))
        data = json.loads(out)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "HE-007"
        assert results[0]["level"] == "warning"
        assert results[0]["message"]["text"] == "Unusual status"
        assert results[0]["properties"]["hint"] == "Check status code"
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "HE-007"


class TestFormatJunit:
    def _make_report(
        self,
        *,
        violations: list[Violation] | None = None,
        error: str | None = None,
    ) -> CheckReport:
        vv = violations or []
        return CheckReport(
            app_path="myapp:app",
            results=[CheckResult("http", path="/", method="GET", violations=vv, error=error)],
        )

    def test_junit_empty(self) -> None:
        out = format_junit(self._make_report())
        root = ET.fromstring(out)  # noqa: S314
        ts = root.find("testsuite")
        assert ts is not None
        assert ts.get("tests") == "1"
        assert ts.get("failures") == "0"

    def test_junit_with_violation(self) -> None:
        v = Violation(rule_id="G-001", severity=Severity.ERROR, message="bad scope")
        out = format_junit(self._make_report(violations=[v]))
        root = ET.fromstring(out)  # noqa: S314
        failure = root.find(".//failure")
        assert failure is not None
        assert "G-001" in (failure.text or "")

    def test_junit_with_error(self) -> None:
        out = format_junit(self._make_report(error="app crashed"))
        root = ET.fromstring(out)  # noqa: S314
        err = root.find(".//error")
        assert err is not None
        assert err.get("message") == "app crashed"
        ts = root.find("testsuite")
        assert ts is not None
        assert ts.get("errors") == "1"


class TestInit:
    def test_init_creates_file(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0
        assert (tmp_path / ".asgion.toml").exists()

    def test_init_exists_no_force_exits_2(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".asgion.toml").write_text("existing")
        runner = CliRunner()
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 2

    def test_init_force_overwrites(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".asgion.toml").write_text("old")
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--force"])
        assert result.exit_code == 0
        content = (tmp_path / ".asgion.toml").read_text()
        assert "profile" in content

    def test_init_pyproject(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--pyproject"])
        assert result.exit_code == 0
        assert "[tool.asgion]" in result.output


class TestWsClose:
    def test_ws_close_without_accept(self) -> None:
        async def ws_close_app(scope, receive, send):  # type: ignore[no-untyped-def]
            if scope["type"] == "http":
                await receive()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                    }
                )
                await send({"type": "http.response.body", "body": b"OK", "more_body": False})
                return
            if scope["type"] != "websocket":
                return
            await receive()  # websocket.connect
            await send({"type": "websocket.close", "code": 1000})

        report = run_check(
            ws_close_app,
            app_path="test:app",
            paths=("ws:/ws",),
            run_lifespan=False,
        )
        assert len(report.results) == 1
        assert report.results[0].scope_type == "websocket"
