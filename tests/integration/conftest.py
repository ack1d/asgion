import asyncio

import pytest

from asgion.core._types import ASGIApp, Message

# Skip all tests in this directory if httpx is not installed.
pytest.importorskip("httpx")


async def drive_lifespan(app: ASGIApp) -> list[Message]:
    """Drive one full lifespan cycle and return sent messages."""
    sent: list[Message] = []
    q: asyncio.Queue[Message] = asyncio.Queue()
    await q.put({"type": "lifespan.startup"})

    async def receive() -> Message:
        return await q.get()

    async def send(message: Message) -> None:
        sent.append(message)
        if message.get("type") == "lifespan.startup.complete":
            await q.put({"type": "lifespan.shutdown"})

    scope: Message = {"type": "lifespan", "asgi": {"version": "3.0"}}
    await app(scope, receive, send)
    return sent
