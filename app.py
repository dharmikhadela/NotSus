import hashlib
import logging
import sys
import uuid
from logging.config import dictConfig
import random
import re
import datetime

import bcrypt
from flask import Flask, redirect, render_template, request, jsonify, session, make_response
from flask_socketio import SocketIO, disconnect, join_room, emit, leave_room
from api.db import users, lobbies_collection

#Setting up logging details.
dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        },
        'request': {
            'format': '[%(asctime)s] %(remote_addr)s requested %(url)s\n%(levelname)s in %(module)s: %(message)s',
        }
    },
    'handlers': {
        'file': {
            'class': 'logging.FileHandler',
            'filename': '/app/logs/logs.txt',
            'formatter': 'default',
            'level': 'INFO'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'default',
            'level': 'INFO'
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['file', 'console']
    }

})

app = Flask(__name__)
app.secret_key = "yoursecretkey"
socketio = SocketIO(app, cors_allowed_origins=["http://localhost:8080","http://127.0.0.1:8080","https://not-sus.cse312.dev"])

clients = {}
rooms = {}
usernames = {}

@app.before_request
def log_request():
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    method = request.method
    path = request.path
    headers = dict(request.headers)
    if 'Cookie' in headers:
        cookies = headers['Cookie']
        cookies = re.sub(r'auth_token=[^;]+', 'auth_token=<REDACTED>', cookies)
        cookies = re.sub(r'session=[^;]+', 'session=<REDACTED>', cookies)

        headers['Cookie'] = cookies
    app.logger.info(f"{ip} {method} {path} | Headers: {headers}")


@app.route('/register', methods=['POST'])
def register_user():
    username = request.form['username']
    password = request.form['password']
    if len(password) < 8:
        app.logger.warning("Password too short")
        return jsonify({"message": "Password must be at least 8 characters long"}), 400
    elif not any(a.isdigit() for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message": "Password must contain at least one digit"}), 400
    elif not any(a.isupper() for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message": "Password must contain at least one uppercase letter"}), 400
    elif not any(a.islower() for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message": "Password must contain at least one lowercase letter"}), 400
    elif not any(a in ["$", "@", "!", "%", "#"] for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message": "Password must contain at least one special character"}), 400
    if users.find_one({"username": username}) is not None:
        return jsonify({"message": "Username taken"}), 400
    auth_token = str(uuid.uuid1())
    response = make_response(jsonify({"message": "Registered successfully."}))
    response.set_cookie("auth_token", auth_token, httponly=True, max_age=2600000)
    users.insert_one({"user_id": str(uuid.uuid1()), "username": username,
                      "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
                      "auth_token": hashlib.sha256(auth_token.encode()).hexdigest(), "score": 0})
    app.logger.info(f"User registered: {username}")
    return jsonify({"message": "Registered successfully."})


@app.route("/register", methods=['GET'])
def serve_register():
    return render_template('register.html')


@app.route("/login", methods=["GET"])
def serve_login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_user():
    username = request.form['username']
    password = request.form['password']
    app.logger.info(f"Login attempt for user: {username}")

    user = users.find_one({"username": username})
    if not user:
        app.logger.warning(f"Login failed: {username} does not exist")
        return jsonify({"message": "Invalid username or password"}), 401

    if bcrypt.checkpw(password.encode(), user["password"]):
        session["username"] = username
        auth_token = str(uuid.uuid1())
        response = make_response(jsonify({"message": "Login successful"}))
        response.set_cookie("auth_token", auth_token, httponly=True, max_age=2600000)
        users.update_one({"username": username},
                         {"$set": {"auth_token": hashlib.sha256(auth_token.encode()).hexdigest()}})
        app.logger.info(f"Login successful for user: {username}")
        return response
    else:
        app.logger.warning(f"Login failed: {username} invalid password")
        return jsonify({"message": "Invalid username or password"}), 401


@app.route("/", methods=["GET"])
def index():
    if authenticate(request) is not None:
        session["username"] = authenticate(request)["username"]
    else:
        return redirect("/login")
    return render_template("landing.html")

@app.route("/landing", methods=["GET"])
def landing():
    return redirect("/")

@app.route("/game/<lobby_id>", methods=["GET"])
def start_game(lobby_id):
    if authenticate(request) is not None:
        session["username"] = authenticate(request)["username"]
    else:
        return redirect("/login")
    lobby = lobbies_collection.find_one({"lobby_id": lobby_id})
    if lobby is None:
        return "Not Found", 404
    return render_template("game.html")


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect("/login")


@app.route("/scoreboard/<lobby_id>", methods=["GET"])
def scoreboard(lobby_id):
    user = authenticate(request)
    if user is not None:
        session["username"] = authenticate(request)["username"]
    else:
        return redirect("/login")
    lobby = lobbies_collection.find_one({"lobby_id": lobby_id})
    if lobby is None:
        return "Not Found", 404
    lobby_users = lobby.get("players")
    all_users = [{"username":user["username"], "score":user["score"]}]
    if lobby_users is not None:
        for user in lobby_users:
            user_entry = users.find_one({"username":user})
            all_users.append({"username":user, "score":user_entry.get("score")})
        # Get all users and their scores, sorted by score descending
        all_users.sort(key=lambda x: x.get("score", 0), reverse=True)

    return render_template("scoreboard.html")

@app.route("/find-lobby", methods=["GET"])
def find_lobby():
    user = authenticate(request)
    if user is not None:
        session["username"] = authenticate(request)["username"]
        users.update_one({"username":user.get("username")}, {"$set":{"score":0}})
    else:
        return redirect("/login")
    lobbies = lobbies_collection.find({"started": False})
    for lobby in lobbies:
        if len(lobby["players"]) <= 25:
            return redirect("/lobby/" + lobby["lobby_id"])
    lobby_id = str(uuid.uuid1())
    lobbies_collection.insert_one({"lobby_id":lobby_id, "players":[], "started": False, "created_at":datetime.datetime.now(datetime.UTC)})
    return redirect("/lobby/" + lobby_id)


@app.route("/lobby/<lobby_id>")
def serve_lobby(lobby_id):
    if authenticate(request) is not None:
        session["username"] = authenticate(request)["username"]
        session["lobby_id"] = lobby_id
    else:
        return redirect("/login")
    lobby = lobbies_collection.find_one({"lobby_id": lobby_id})
    if lobby is None:
        return "Not Found", 404
    return render_template("lobby.html")

@socketio.on('score_update')
def send_score_update(data):
    emit('score_update', to=data["lobby_id"])

@socketio.on('join_lobby')
def handle_join_lobby(data):
    username = data['username']
    room_id = data['roomID']

    join_room(room_id)
    print(f"{username} has joined room {room_id}!")

    if room_id not in rooms:
        rooms[room_id] = []


    lobbies_collection.update_one({"lobby_id":room_id},{"$push":{"players":username}})

    rooms[room_id].append(username)
    clients[request.sid] = {
        "username": username,
        "room_id": room_id,
        "x": random.randint(-10, 10),
        "y": random.randint(-10, 10),
        "direction": "down"
    }

    for existing_user in rooms[room_id]:
        if existing_user != username:
            emit('user_joined', existing_user, to=request.sid)

    emit('user_joined', username, to=room_id)

@app.route("/api/me")
def get_me():
    if "auth_token" in request.cookies:
        user = users.find_one({"auth_token": hashlib.sha256(request.cookies["auth_token"].encode()).hexdigest()})
        if user is not None:
            lobby_id = session.get("lobby_id", None)
            return jsonify({"username": user["username"], "lobby_id": lobby_id})
    return jsonify({"username": "NOBODY.", "lobby_id": None})

@app.route("/api/scores/<lobby_id>")
def get_scores(lobby_id):
    lobby = lobbies_collection.find_one({"lobby_id":lobby_id})
    if lobby is None:
        return jsonify({"players": {}})
    players = {}
    players_list = lobby.get("players")
    for player in players_list:
        user = users.find_one({"username":player})
        players[player] = user.get("score")
    return jsonify({"players":players})


@socketio.on('rejoin')
def handle_rejoin(data):
    lobby_id = data.get('lobby_id')
    username = data.get('username')
    join_room(lobby_id)
    clients[request.sid] = {"x": 0, "y": 0, "direction": "down", "username": username, "room_id":lobby_id}
    if lobby_id not in rooms:
        rooms[lobby_id] = []
    if username not in rooms[lobby_id]:
        rooms[lobby_id].append(username)
    emit('user_joined', username, to=lobby_id)
    lobby = lobbies_collection.find_one({"lobby_id":lobby_id})
    if lobby is not None:
        if username not in lobby.get("players"):
            lobbies_collection.update_one({"lobby_id": lobby_id}, {"$push": {"players": username}})
        app.logger.info(f"User {username} rejoined room {lobby_id}")
    else:
        app.logger.info(f"User {username} attempted to join room {lobby_id}, but no room exists")

@socketio.on('connect')
def on_connect():
    clients[request.sid] = {"x": 0, "y": 0, "direction": "down", "username": None}
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    broadcast_state()
    print(f"Client disconnected: {request.sid}")
    for room_id, users in rooms.items():
        # Check if the user was in the room (by matching the session ID)
        for username in users:
            # You can add custom logic to match the user with request.sid (session ID)
            # Here, we'll assume you know which user is connected to which sid

            # If the user is found, remove them from the room
            if username == clients[request.sid]["username"]:  # You would match based on session/user info
                users.remove(username)
                leave_room(room_id)
                # lobbies_collection.update_one({"lobby_id": room_id}, {"$pull": {"players": username}})
                print(f"{username} has left room {room_id}.")

                # Notify everyone in the room that the user has left
                emit('user_left', username, to=room_id)
                break
    if request.sid in clients:
        del clients[request.sid]

@socketio.on('init')
def on_init(data):
    if request.sid in clients:
        clients[request.sid]["username"] = data.get("username")
    broadcast_state()

@socketio.on('move')
def on_move(data):
    if request.sid in clients:
        clients[request.sid]["x"] = data.get("x", 0)
        clients[request.sid]["y"] = data.get("y", 0)
        clients[request.sid]["direction"] = data.get("direction", "down")
        broadcast_state()

@socketio.on('hit')
def on_hit(data):
    hit_x = data.get("x")
    hit_y = data.get("y")
    shooter_sid = request.sid
    shooter_room = clients[shooter_sid].get("room_id")

    for sid, player in list(clients.items()):
        if player.get("username") == data.get("shooter"):
            continue  # Don't allow shooting yourself
        if sid == shooter_sid:
            continue
        if player.get("room_id") != shooter_room:
            continue  # Only allow hits within the same room

        px = player["x"]
        py = player["y"]

        if abs(px - hit_x) < 25 and abs(py - hit_y) < 25:
            try:
                # Emit kill event with shooter information
                socketio.emit('killed', {
                    'victim': player['username'],
                    'shooter': data.get("shooter")
                }, to=sid)
                disconnect(sid)
            except Exception as e:
                print(f"Error killing client {sid}: {e}")

            if sid in clients:
                del clients[sid]

            update_score(shooter_sid)  # Update the score for the shooter
            broadcast_state()  # Broadcast the new state
            emit('score_update', to=shooter_room)  # Send updated score to the room
            break

@socketio.on('request_start')
def on_request_start(data):
    game = data.get("lobby_id")
    lobbies_collection.update_one({"lobby_id":game}, {"$set":{"started":True}})
    emit('start_game', {"lobby_id":game}, to=game)

@socketio.on('shoot_bullet')
def on_shoot_bullet(data):
    room_id = data.get('lobby_id')
    emit('bullet_fired', data, to=room_id)

def broadcast_state():
    # Collect all players grouped by room
    room_states = {}

    for sid, client in clients.items():
        room_id = client.get("room_id")
        if room_id:
            room_states.setdefault(room_id, []).append({
                "username": client.get("username"),
                "x": client.get("x"),
                "y": client.get("y"),
                "direction": client.get("direction"),
                "room_id":room_id
            })

    for room_id, players in room_states.items():
        print(room_id)
        print(players)
        socketio.emit('update', {"players": players}, to=room_id)


def update_score(sid):
    client = clients.get(sid)
    if not client:
        return
    username = client.get("username")
    if username:
        users.update_one(
            {"username": username},
            {"$inc": {"score": 1}}
        )


def authenticate(request):
    if "auth_token" in request.cookies:
        return users.find_one({"auth_token": hashlib.sha256(request.cookies["auth_token"].encode()).hexdigest()})
    else:
        return None

#For logging and giving errors, use format:
# app.logger.info() [Whatever you want to show as an error]
# abort(401) [The status code, if needed]

#Use this for development, if required.
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
