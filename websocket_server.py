import asyncio
import websockets
import json

clients = {}

async def handler(websocket):
    clients[websocket] = {"x": 0, "y": 0, "direction": "down"}

    try:
        async for message in websocket:
            data = json.loads(message)
            if data["type"] == "move":
                clients[websocket] = {
                    "x": data["x"],
                    "y": data["y"],
                    "direction": data["direction"]
                }
            await broadcast()
    except:
        pass
    finally:
        del clients[websocket]
        await broadcast()

async def broadcast():
    state = {
        "type": "update",
        "players": list(clients.values())
    }
    message = json.dumps(state)
    await asyncio.gather(*[ws.send(message) for ws in clients if ws.open])

async def main():
    # print("WebSocket server starting on ws://localhost:6789")
    async with websockets.serve(handler, "0.0.0.0", 6789):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
