import json

import pytest
from click.testing import CliRunner

from asgion.cli._loader import LoadError, load_app
from asgion.cli._output import (
    format_json,
    format_rules_json,
    format_rules_text,
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
        assert f"{len(ALL_RULES)} rules" in text
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
        assert f"{len(ALL_RULES)} rules" in result.output

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
        assert f"filtered from {len(ALL_RULES)}" in result.output
        for line in result.output.splitlines():
            if line.startswith("  ") and line[2:].strip() and line[2:].strip()[0].isalpha():
                rule_id = line.split()[0]
                assert rule_id.startswith(("HE-", "HF-", "HS-", "EX-")), rule_id

    def test_rules_severity_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules", "--no-color", "--severity", "warning"])
        assert result.exit_code == 0
        assert f"filtered from {len(ALL_RULES)}" in result.output
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
        assert f"5 rules (filtered from {total})" in text

    def test_check_ws_path(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_ws_app",
                "--no-color",
                "--no-lifespan",
                "--path",
                "ws:/ws",
            ],
        )
        assert result.exit_code == 0
        assert "WS /ws" in result.output
        assert "No violations found." in result.output

    def test_check_wss_prefix(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_ws_app",
                "--no-color",
                "--no-lifespan",
                "--path",
                "wss:/ws",
            ],
        )
        assert result.exit_code == 0
        assert "WS /ws" in result.output

    def test_check_http_prefix(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                "tests._cli_fixtures:good_lifespan_app",
                "--no-color",
                "--no-lifespan",
                "--path",
                "http:/api",
            ],
        )
        assert result.exit_code == 0
        assert "GET /api" in result.output

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
