from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from asgion.core._types import Scope


def _should_trace(sample_rate: float, scope: Scope) -> bool:
    """Deterministic, lock-free sampling decision.

    Uses blake2b hash of method+path for consistent sampling:
    same endpoint always produces the same decision for a given rate.
    """
    if sample_rate >= 1.0:
        return True
    if sample_rate <= 0.0:
        return False
    key = (scope.get("method", "") + scope.get("path", "")).encode()
    h = int.from_bytes(hashlib.blake2b(key, digest_size=4).digest(), "big")
    return (h % 10_000) < int(sample_rate * 10_000)
