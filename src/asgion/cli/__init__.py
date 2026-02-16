try:
    from asgion.cli.main import cli as main
except ImportError:

    def main() -> None:  # type: ignore[misc]
        """Stub when click is not installed."""
        import sys

        print("CLI requires click. Install with: pip install asgion[cli]")  # noqa: T201
        sys.exit(1)


__all__ = ["main"]
