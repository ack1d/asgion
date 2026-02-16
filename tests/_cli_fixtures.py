async def good_app(scope, receive, send):  # type: ignore[no-untyped-def]
    await receive()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"OK", "more_body": False})


async def bad_app(scope, receive, send):  # type: ignore[no-untyped-def]
    await receive()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": "not bytes"})


async def good_lifespan_app(scope, receive, send):  # type: ignore[no-untyped-def]
    if scope["type"] == "lifespan":
        msg = await receive()
        if msg["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        msg = await receive()
        if msg["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
        return
    await receive()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"OK", "more_body": False})


not_callable = "i am a string"
