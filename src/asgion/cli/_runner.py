from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from asgion.cli._driver import DEFAULT_TIMEOUT, drive
from asgion.core._types import SEVERITY_LEVEL, Severity
from asgion.core.inspector import Inspector

if TYPE_CHECKING:
    from asgion.core.config import AsgionConfig
    from asgion.core.violation import Violation


@dataclass
class CheckResult:
    scope_type: str
    path: str = ""
    method: str = ""
    violations: list[Violation] = field(default_factory=list)
    error: str | None = None


@dataclass
class CheckReport:
    app_path: str
    results: list[CheckResult] = field(default_factory=list)
    elapsed_s: float = 0.0

    @property
    def all_violations(self) -> list[Violation]:
        vv: list[Violation] = []
        for r in self.results:
            vv.extend(r.violations)
        return vv

    def filtered(self, min_severity: Severity) -> list[Violation]:
        level = SEVERITY_LEVEL[min_severity]
        return [v for v in self.all_violations if SEVERITY_LEVEL[v.severity] >= level]


def run_check(
    app: object,
    *,
    app_path: str,
    paths: tuple[str, ...] = ("/",),
    config: AsgionConfig | None = None,
    exclude_rules: set[str] | None = None,
    run_lifespan: bool = True,
    default_method: str = "GET",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
    scope_timeout: float = DEFAULT_TIMEOUT,
) -> CheckReport:
    """Run ASGI protocol checks and return a report.

    Each entry in ``paths`` is a plain path (e.g. ``/api``) defaulting to HTTP,
    or a prefixed path to specify the scope type:
    ``http:/path``, ``https:/path``, ``ws:/path``, ``wss:/path``.
    """
    inspector = Inspector(
        app,  # type: ignore[arg-type]
        config=config,
        exclude_rules=exclude_rules,
    )
    report = CheckReport(app_path=app_path)
    t0 = time.perf_counter()

    async def _run() -> None:
        runs = await drive(
            inspector,
            paths,
            run_lifespan=run_lifespan,
            default_method=default_method,
            headers=headers,
            body=body,
            scope_timeout=scope_timeout,
        )
        violations = inspector.violations
        for i, run in enumerate(runs):
            start = run.violation_start
            end = runs[i + 1].violation_start if i + 1 < len(runs) else len(violations)
            report.results.append(
                CheckResult(
                    scope_type=run.scope_type,
                    path=run.path,
                    method=run.method,
                    violations=violations[start:end],
                    error=run.error,
                )
            )

    asyncio.run(_run())
    report.elapsed_s = time.perf_counter() - t0
    return report
