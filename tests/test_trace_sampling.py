"""Tests for trace sampling logic."""

from __future__ import annotations

from asgion.trace._sampling import _should_trace


class TestShouldTrace:
    def test_rate_1_always_traces(self) -> None:
        assert _should_trace(1.0, {"method": "GET", "path": "/"}) is True
        assert _should_trace(1.0, {}) is True

    def test_rate_0_never_traces(self) -> None:
        assert _should_trace(0.0, {"method": "GET", "path": "/"}) is False
        assert _should_trace(0.0, {}) is False

    def test_deterministic(self) -> None:
        scope = {"method": "GET", "path": "/api/users"}
        result = _should_trace(0.5, scope)
        for _ in range(100):
            assert _should_trace(0.5, scope) == result

    def test_different_paths_may_differ(self) -> None:
        results = set()
        for i in range(100):
            results.add(_should_trace(0.5, {"method": "GET", "path": f"/path/{i}"}))
        assert len(results) == 2  # both True and False should appear

    def test_lifespan_no_path(self) -> None:
        result = _should_trace(0.5, {"type": "lifespan"})
        assert isinstance(result, bool)

    def test_above_1_always_traces(self) -> None:
        assert _should_trace(1.5, {"method": "GET", "path": "/"}) is True

    def test_below_0_never_traces(self) -> None:
        assert _should_trace(-0.5, {"method": "GET", "path": "/"}) is False
