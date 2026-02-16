import importlib
import sys
from pathlib import Path


class LoadError(Exception):
    """Raised when an ASGI app cannot be loaded."""


def load_app(app_path: str, *, cwd: str | None = None) -> object:
    """Load an ASGI application from a ``module:attribute`` string.

    Adds *cwd* (default: current directory) to ``sys.path[0]`` so that
    local modules can be imported, matching uvicorn behaviour.
    """
    if ":" not in app_path:
        msg = f"Invalid app path {app_path!r} - expected 'module:attribute' (e.g. 'myapp:app')"
        raise LoadError(msg)

    module_str, _, attr_str = app_path.partition(":")

    target = str(Path(cwd).resolve()) if cwd else str(Path.cwd())
    if sys.path[0] != target:
        sys.path.insert(0, target)

    try:
        module = importlib.import_module(module_str)
    except ImportError as exc:
        msg = f"Could not import module {module_str!r}: {exc}"
        raise LoadError(msg) from exc

    try:
        app = getattr(module, attr_str)
    except AttributeError:
        msg = f"Module {module_str!r} has no attribute {attr_str!r}"
        raise LoadError(msg) from None

    if not callable(app):
        msg = f"{app_path!r} is not callable (got {type(app).__name__})"
        raise LoadError(msg)

    return app
