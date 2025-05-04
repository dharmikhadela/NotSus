import hashlib
import logging
import sys
import uuid
from logging.config import dictConfig
import random
import re
import datetime
import os
from werkzeug.utils import secure_filename
from PIL import Image

import bcrypt
from flask import Flask, redirect, render_template, request, jsonify, session, make_response
from flask_socketio import SocketIO, disconnect, join_room, emit, leave_room
from api.db import users, lobbies_collection
from pymongo import DESCENDING
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

UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

@app.route('/leaderboard')
def leaderboard():
    user_list = list(users.find({}, {"username": 1, "lifetime_kills": 1, "_id": 0}).sort("lifetime_kills", DESCENDING))
    # Rename field for use in template
    for user in user_list:
        user["kills"] = user.get("lifetime_kills", 0)
    return render_template('leaderboard.html', users=user_list)


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
                      "auth_token": hashlib.sha256(auth_token.encode()).hexdigest(), "score": 0,
                       "lifetime_wins": 0, "lifetime_kills": 0, "lifetime_deaths": 0, "kill_death": 0.0}) # For player stats
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
def serve_find_lobby():
    all_lobbies = list(lobbies_collection.find({"started": False}))
    for lobby in all_lobbies:
        lobby["players"] = lobby.get("players", [])
        lobby["player_count"] = len(lobby["players"])
        if lobby["player_count"] > 4:
            lobby["extra_count"] = lobby["player_count"] - 4
            lobby["players_display"] = lobby["players"][:4]
        else:
            lobby["extra_count"] = 0
            lobby["players_display"] = lobby["players"]
    return render_template("find-lobbies.html", lobbies=all_lobbies)

@app.route("/random")
def find_random_lobby():
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
    lobby_id = create_lobby()
    return redirect("/lobby/" + lobby_id)

@app.route("/new")
def new_lobby():
    lobby_id = create_lobby()
    return redirect("/lobby/" + lobby_id)

def create_lobby():
    lobby_id = str(uuid.uuid1())
    lobbies_collection.insert_one(
        {"lobby_id": lobby_id, "players": [], "all_players": [], "dead": [], "scores": {}, "started": False, "created_at": datetime.datetime.now(datetime.UTC)})
    return lobby_id


@app.route("/lobby/<lobby_id>")
def serve_lobby(lobby_id):
    if authenticate(request) is not None:
        session["username"] = authenticate(request)["username"]
        session["lobby_id"] = lobby_id
        print(f"{session["username"]}, {session["lobby_id"]}")
    else:
        return redirect("/login")
    lobby = lobbies_collection.find_one({"lobby_id": lobby_id})
    if lobby is None:
        return "Not Found", 404
    return render_template("lobby.html")

@socketio.on('score_update')
def send_score_update(data):
    lobby = lobbies_collection.find_one({"lobby_id":data["lobby_id"]})
    if len(lobby.get("dead")) == len(lobby.get("all_players")) - 1:
        socketio.emit('game_over', to=data["lobby_id"])
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
    lobbies_collection.update_one({"lobby_id": room_id}, {"$push": {"all_players": username}})
    lobbies_collection.update_one(
        {"lobby_id": room_id},
        {"$set": {f"scores.{username}": 0}}
    )

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
            return jsonify({"username": user["username"], "lobby_id": lobby_id, "profile_pic": user.get("profile_pic")})
    return jsonify({"username": "NOBODY.", "lobby_id": None, "profile_pic": None})

@app.route("/api/scores/<lobby_id>")
def get_scores(lobby_id):
    lobby = lobbies_collection.find_one({"lobby_id":lobby_id})
    if lobby is None:
        return jsonify({"players": {}})
    scores = lobby.get("scores")
    return jsonify({"players":scores})

@app.route('/api/update_winner', methods=['POST'])
def update_winner():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'message': 'Missing username'}), 400

    users.update_one(
        {"username": username},
        {"$inc": {"lifetime_wins": 1}}
    )

    return jsonify({'message': 'Winner updated'})


@app.route('/profile-pic', methods=['POST'])
def upload_profile_pic():
    if 'auth_token' not in request.cookies:
        return jsonify({'error': 'Unauthorized'}), 401

    user = users.find_one({"auth_token": hashlib.sha256(request.cookies["auth_token"].encode()).hexdigest()})
    if user is None:
        return jsonify({'error': 'User not found'}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"{user['username']}.{ext}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Validate it's a real image
        try:
            file.seek(0)
            image = Image.open(file)
            image.verify()
            file.seek(0)
        except Exception:
            return jsonify({'error': 'Invalid image file'}), 400

        file.save(filepath)

        users.update_one({"_id": user["_id"]}, {"$set": {"profile_pic": filename}})

        return jsonify({'success': True, 'filename': filename})

    return jsonify({'error': 'Invalid file type'}), 400

@app.route("/stats")
def view_stats():
    user = authenticate(request)
    if user is None:
        return redirect("/login")
    username = user.get("username")
    data = users.find_one({"username": username})
    if not data:
        return "User not found", 404

    stats = {
        "score": data.get("score", 0),
        "lifetime_kills": data.get("lifetime_kills", 0),
        "lifetime_deaths": data.get("lifetime_deaths", 0),
        "lifetime_wins": data.get("lifetime_wins", 0),
        "kill_death": round(data.get("kill_death", 0.0), 2)
    }
    return render_template("stats.html", username=username, stats=stats)


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
        if username not in lobby.get("players") and username not in lobby.get("dead"):
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
    sid = request.sid
    print(f"Client disconnected: {sid}")

    if sid not in clients:
        print(f"SID {sid} not found in clients. Skipping cleanup.")
        return

    client_data = clients[sid]
    username = client_data.get("username")
    print(f"Disconnecting user: {username}")
    print(f"All rooms: {rooms.items()}")

    for room_id in list(rooms.keys()):
        users = rooms.get(room_id, [])
        print(f"Checking room: {room_id} with users: {users}")

        lobby = lobbies_collection.find_one({"lobby_id": room_id})
        if not lobby:
            print(f"No lobby found in DB for room {room_id}. Skipping.")
            continue

        if username in lobby.get("players", []):
            print(f"{username} is in lobby {room_id}, removing...")
            update_ops = [{"$pull": {"players": username}}]

            for op in update_ops:
                lobbies_collection.update_one({"lobby_id": room_id}, op)

            emit('user_left', username, to=room_id)

            updated_lobby = lobbies_collection.find_one({"lobby_id": room_id})
            if updated_lobby and not updated_lobby.get("started") and len(updated_lobby.get("players", [])) == 0:
                lobbies_collection.find_one_and_delete({"lobby_id": room_id})
                print(f"Lobby {room_id} deleted because it's empty and not started.")

        if username in users:
            users.remove(username)
            leave_room(room_id)
            print(f"{username} removed from in-memory room {room_id}")

    del clients[sid]
    broadcast_state()
    print(f"Cleanup complete for SID: {sid}")


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
        lobby = lobbies_collection.find_one({"lobby_id": shooter_room})
        if player.get("username") == data.get("shooter"):
            continue  # Don't allow shooting yourself
        if sid == shooter_sid:
            continue
        if player.get("room_id") != shooter_room:
            continue  # Only allow hits within the same room
        if player.get("username") in lobby.get("dead"):
            continue
        px = player["x"]
        py = player["y"]

        if abs(px - hit_x) < 25 and abs(py - hit_y) < 25:
            if player.get("username") not in lobby.get("dead"):
                lobbies_collection.update_one({"lobby_id": shooter_room}, {"$push": {"dead": player['username']}})
                lobbies_collection.update_one({"lobby_id": shooter_room}, {"$pull": {"players": player['username']}})

            if len(lobby.get("dead")) == len(lobby.get("all_players")) - 1:
                socketio.emit('game_over', to=shooter_room)
            try:
                # Emit kill event with shooter information
                socketio.emit('killed', {
                    'victim': player['username'],
                    'shooter': data.get("shooter")
                }, to=sid)
                update_stats_on_death(player['username'])
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
            # Fetch profile picture from your database (assuming `users` collection has a `profile_pic` field)
            username = client.get("username")
            user = users.find_one({"username": username})
            profile_pic = user.get("profile_pic") if user else None

            room_states.setdefault(room_id, []).append({
                "username": username,
                "x": client.get("x"),
                "y": client.get("y"),
                "direction": client.get("direction"),
                "room_id": room_id,
                "profile_pic": profile_pic,  # Add profile picture to player data
            })


    for room_id, players in room_states.items():
        print(room_id)
        print(players)
        socketio.emit('update', {"players": players}, to=room_id)


def update_score(sid):
    client = clients.get(sid)
    if not client:
        print(f"update_score: No client found for sid {sid}")
        return

    username = client.get("username")
    room_id = client.get("room_id")
    if not username or not room_id:
        print(f"update_score: Missing username or room_id for sid {sid}")
        return

    # --- Global stat update ---
    player_stats = users.find_one({"username": username})
    if player_stats:
        kills = player_stats.get("lifetime_kills", 0) + 1
        deaths = player_stats.get("lifetime_deaths", 0)
        kd = kills / deaths if deaths > 0 else float(kills)

        users.update_one(
            {"username": username},
            {
                "$inc": {"score": 1, "lifetime_kills": 1},
                "$set": {"kill_death": kd}
            }
        )
        print(f"Global stats updated for {username}: kills={kills}, kd={kd}")
    else:
        print(f"update_score: Could not find user {username} in users collection")

    # --- Lobby-specific score update ---
    lobby = lobbies_collection.find_one({"lobby_id": room_id})
    if not lobby:
        print(f"update_score: No lobby found with id {room_id}")
        return

    current_scores = lobby.get("scores", {})
    new_score = current_scores.get(username, 0) + 1

    lobbies_collection.update_one(
        {"lobby_id": room_id},
        {"$set": {f"scores.{username}": new_score}}
    )

    print(f"Lobby score updated: {username} = {new_score}")

def authenticate(request):
    if "auth_token" in request.cookies:
        return users.find_one({"auth_token": hashlib.sha256(request.cookies["auth_token"].encode()).hexdigest()})
    else:
        return None


def update_stats_on_death(killed_user):
    player_stats = users.find_one({"username": killed_user})
    kills = player_stats.get("lifetime_kills")
    deaths = player_stats.get("lifetime_deaths") + 1
    if deaths == 0.0:
        kd = float(kills)
    else:
        kd = kills / deaths

    users.update_one({"username": killed_user},
                     {"$inc": {"lifetime_deaths": 1},
                      "$set": {"kill_death": kd}}
                     )



#For logging and giving errors, use format:
# app.logger.info() [Whatever you want to show as an error]
# abort(401) [The status code, if needed]

#Use this for development, if required.
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
