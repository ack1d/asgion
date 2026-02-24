from asgion.core._types import ASGIApp
from asgion.core.config import AsgionConfig
from asgion.core.context import ViolationCallback
from asgion.validators.base import ValidatorRegistry


def inspect(
    app: ASGIApp,
    *,
    config: AsgionConfig | None = None,
    strict: bool = False,
    on_violation: ViolationCallback | None = None,
    exclude_paths: list[str] | None = None,
    exclude_rules: set[str] | None = None,
    registry: ValidatorRegistry | None = None,
) -> ASGIApp:
    """Wrap an ASGI app with protocol validation.

    Args:
        app: The ASGI application to wrap.
        config: Rule filter settings and thresholds. Defaults to ``AsgionConfig()``.
        strict: If True, raise ASGIProtocolError on any violation.
        on_violation: Optional callback for each violation (called in real-time).
        exclude_paths: Paths to skip validation for.
        exclude_rules: Extra rule IDs to suppress on top of
                       ``config.exclude_rules``.
        registry: Custom validator registry. Uses defaults if None.

    Returns:
        Wrapped ASGI application with protocol validation.

    Example::

        from asgion import inspect

        app = inspect(app)  # Zero config, full validation.

    """
    from asgion.core.inspector import Inspector

    return Inspector(
        app,
        config=config,
        strict=strict,
        on_violation=on_violation,
        exclude_paths=exclude_paths,
        exclude_rules=exclude_rules,
        registry=registry,
    ).asgi_app
