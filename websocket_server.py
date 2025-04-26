import asyncio
import websockets
import json

clients = {}

async def handler(websocket):
    clients[websocket] = {"x": 0, "y": 0, "direction": "down", "username": None}

    try:
        async for message in websocket:
            data = json.loads(message)
            if data["type"] == "init":
                clients[websocket]["username"] = data["username"]
            if data["type"] == "move":
                clients[websocket]["x"] = data["x"]
                clients[websocket]["y"] = data["y"]
                clients[websocket]["direction"] = data["direction"]
            if data["type"] == "hit":
                await handle_hit(data, websocket)

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


async def handle_hit(data, shooter_ws):
    hit_x, hit_y = data["x"], data["y"]

    # Find which player was hit
    for ws, player in clients.items():
        if ws == shooter_ws:
            continue  # Can't hit yourself

        px, py = player["x"], player["y"]

        if abs(px - hit_x) < 25 and abs(py - hit_y) < 25:  # Adjust hitbox sensitivity
            # Player hit -> remove them
            del clients[ws]

            # Add point to shooter (database update)
            await update_score(shooter_ws)

            # 💥 New: Tell everyone about the change
            await broadcast()

            # 💥 New: Tell the killed player to redirect
            try:
                await ws.send(json.dumps({"type": "killed"}))
            except:
                pass

            break

from api.db import users  # same database as Flask app

async def update_score(ws):
    username = clients[ws].get("username")
    users.update_one(
        {"username": username},
        {"$inc": {"score": 1}})



if __name__ == "__main__":
    asyncio.run(main())
