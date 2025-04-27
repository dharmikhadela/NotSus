import hashlib
import logging
import sys
import uuid
from logging.config import dictConfig

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
            'filename': 'logs.txt',
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
socketio = SocketIO(app)

clients = {}
rooms = {}
usernames = {}

@app.route("/", methods=["GET"])
def index():
    return redirect("/register")

@app.before_request
def log_request():
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    method = request.method
    path = request.path
    headers = dict(request.headers)
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


@app.route("/landing", methods=["GET"])
def landing():
    if "auth_token" in request.cookies:
        user = users.find_one({"auth_token": hashlib.sha256(request.cookies["auth_token"].encode()).hexdigest()})
        if user is not None:
            session["username"] = user["username"]
        else:
            return redirect("/login")
    return render_template("landing.html")


@app.route("/start", methods=["GET"])
def start_game():
    if "username" not in session:
        return redirect("/login")
    return render_template("game.html")


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect("/login")


@app.route("/scoreboard", methods=["GET"])
def scoreboard():
    if "username" not in session:
        return redirect("/login")

    # Get all users and their scores, sorted by score descending
    all_users = list(users.find({}, {"_id": 0, "username": 1, "score": 1}))
    all_users.sort(key=lambda x: x.get("score", 0), reverse=True)

    return render_template("scoreboard.html", users=all_users)


@app.route("/find-lobby", methods=["GET"])
def find_lobby():
    if "auth_token" in request.cookies:
        user = users.find_one({"auth_token": hashlib.sha256(request.cookies["auth_token"].encode()).hexdigest()})
        if user is not None:
            session["username"] = user["username"]
        else:
            return redirect("/login")

    lobbies = lobbies_collection.find({"started": False})
    for lobby in lobbies:
        if len(lobby["players"]) <= 25:
            pass  # join lobby
    lobby_id = str(uuid.uuid1())

    return redirect("/lobby/" + lobby_id)


@app.route("/lobby/<lobby_id>")
def serve_lobby(lobby_id):
    # lobby = lobbies_collection.find_one({"lobby_id": lobby_id})
    # if lobby is None:
    #     return "Not Found", 404
    return render_template("lobby.html")

@socketio.on('join_lobby')
def handle_join_lobby(data):
    username = data['username']
    room_id = data['roomID']

    # Join the user to the specified room
    join_room(room_id)
    print(f"{username} has joined room {room_id}!")

    if room_id not in rooms:
        rooms[room_id] = []

    rooms[room_id].append(username)
    clients[request.sid]["username"] = username

    for existing_user in rooms[room_id]:
        if existing_user != username:  # Don't send to the joining user themselves
            emit('user_joined', existing_user, to=request.sid)

    emit('user_joined', username, to=room_id)

@app.route("/api/me")
def get_me():
    if "auth_token" in request.cookies:
        user = users.find_one({"auth_token": hashlib.sha256(request.cookies["auth_token"].encode()).hexdigest()})
        if user is not None:
            return jsonify({"username":user["username"]})
        else:
            return jsonify({"username":"NOBODY."})
    return jsonify({"username":"NOBODY."})

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

    for sid, player in list(clients.items()):
        if sid == shooter_sid:
            continue

        px = player["x"]
        py = player["y"]

        if abs(px - hit_x) < 25 and abs(py - hit_y) < 25:
            try:
                socketio.emit('killed', to=sid)
                disconnect(sid)
            except Exception as e:
                print(f"Error killing client {sid}: {e}")

            if sid in clients:
                del clients[sid]
            update_score(shooter_sid)
            broadcast_state()
            break

def broadcast_state():
    state = {
        "players": list(clients.values())
    }
    socketio.emit('update', state)

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



#For logging and giving errors, use format:
# app.logger.info() [Whatever you want to show as an error]
# abort(401) [The status code, if needed]

#Use this for development, if required.
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
