import asyncio
import pathlib
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from asgion import BUILTIN_PROFILES, Inspector
from asgion.core._types import ASGIApp, Message

CONFIG = BUILTIN_PROFILES["recommended"]
STRICT = BUILTIN_PROFILES["strict"]

_INTEGRATION_DIR = pathlib.Path(__file__).parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if item.path and item.path.is_relative_to(_INTEGRATION_DIR):
            item.add_marker(pytest.mark.integration)


@pytest.fixture
def app(asgi_inspect: Callable[..., Inspector], raw_app: ASGIApp) -> Inspector:
    return asgi_inspect(raw_app, config=CONFIG)


@pytest.fixture
async def client(app: Inspector) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture
def app_strict(asgi_inspect: Callable[..., Inspector], raw_app: ASGIApp) -> Inspector:
    return asgi_inspect(raw_app, config=STRICT)


@pytest.fixture
async def client_strict(app_strict: Inspector) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app_strict, raise_app_exceptions=False)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


_LIFESPAN_TIMEOUT = 5.0


async def drive_lifespan(app: ASGIApp) -> list[Message]:
    """Drive one full lifespan cycle and return sent messages."""
    sent: list[Message] = []
    q: asyncio.Queue[Message] = asyncio.Queue()
    await q.put({"type": "lifespan.startup"})

    async def receive() -> Message:
        return await q.get()

    async def send(message: Message) -> None:
        sent.append(message)
        if message.get("type") in {"lifespan.startup.complete", "lifespan.startup.failed"}:
            await q.put({"type": "lifespan.shutdown"})

    scope: dict[str, object] = {"type": "lifespan", "asgi": {"version": "3.0"}}
    await asyncio.wait_for(app(scope, receive, send), timeout=_LIFESPAN_TIMEOUT)
    return sent
