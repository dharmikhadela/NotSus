import logging
import sys
from logging.config import dictConfig

import bcrypt
from flask import Flask, redirect, render_template, request, jsonify, session

from api.db import users

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
        'filename': 'logs/logs.txt',
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

@app.before_request
def log_request():
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    method = request.method
    path = request.path
    headers = dict(request.headers)
    app.logger.info(f"{ip} {method} {path} | Headers: {headers}")

@app.route("/", methods=["GET"])
def index():
    return redirect("/register")

@app.route('/register', methods=['POST'])
def register_user():
    username = request.form['username']
    password = request.form['password']
    if len(password) < 8:
        app.logger.warning("Password too short")
        return jsonify({"message":"Password must be at least 8 characters long"}), 400
    elif not any(a.isdigit() for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message":"Password must contain at least one digit"}), 400
    elif not any(a.isupper() for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message":"Password must contain at least one uppercase letter"}), 400
    elif not any(a.islower() for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message":"Password must contain at least one lowercase letter"}), 400
    elif not any (a in ["$", "@", "!", "%", "#"] for a in password):
        app.logger.warning("Password not following standards")
        return jsonify({"message":"Password must contain at least one special character"}), 400
    if users.find_one({"username":username}) is not None:
        return jsonify({"message": "Username taken"}), 400
    users.insert_one({"username":username, "password":bcrypt.hashpw(password.encode(), bcrypt.gensalt())})
    app.logger.info(f"User registered: {username}")
    return jsonify({"message":"Registered successfully."})


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
        app.logger.info(f"Login successful for user: {username}")
        return jsonify({"message": "Login successful"})
    else:
        app.logger.warning(f"Login failed: {username} invalid password")
        return jsonify({"message": "Invalid username or password"}), 401

@app.route("/landing", methods=["GET"])
def landing():
    if "username" not in session:
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


#For logging and giving errors, use format: 
# app.logger.info() [Whatever you want to show as an error]
# abort(401) [The status code, if needed]

#Use this for development, if required.
if __name__ == "__main__":
     app.run(host="0.0.0.0", port=5000, debug=True)
