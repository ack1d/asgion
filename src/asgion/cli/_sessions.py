from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from asgion.core._types import Message, Receive, Scope, Send


def lifespan_session() -> tuple[Scope, Receive, Send]:
    scope: Scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
    phase = "startup"

    async def receive() -> Message:
        nonlocal phase
        if phase == "startup":
            phase = "started"
            return {"type": "lifespan.startup"}
        if phase == "shutdown":
            phase = "done"
            return {"type": "lifespan.shutdown"}
        await asyncio.sleep(999)
        return {"type": "lifespan.shutdown"}

    async def send(message: Message) -> None:
        nonlocal phase
        msg_type = message.get("type", "")
        if msg_type in ("lifespan.startup.complete", "lifespan.startup.failed"):
            phase = "shutdown"

    return scope, receive, send


def ws_session(*, path: str = "/ws") -> tuple[Scope, Receive, Send]:
    scope: Scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "subprotocols": [],
    }
    phase = "connect"

    async def receive() -> Message:
        nonlocal phase
        if phase == "connect":
            phase = "connected"
            return {"type": "websocket.connect"}
        if phase == "message":
            phase = "disconnect"
            return {"type": "websocket.receive", "text": ""}
        if phase == "disconnect":
            phase = "done"
            return {"type": "websocket.disconnect", "code": 1000}
        await asyncio.sleep(999)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Message) -> None:
        nonlocal phase
        msg_type = message.get("type", "")
        if msg_type == "websocket.accept" and phase == "connected":
            phase = "message"
        elif msg_type == "websocket.close":
            phase = "done"

    return scope, receive, send


def http_session(*, path: str = "/", method: str = "GET") -> tuple[Scope, Receive, Send]:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [],
    }
    request_sent = False

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(999)
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        pass

    return scope, receive, send
