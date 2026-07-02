from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from models import initialize_storage
from auth import register_user, login_user, list_users
from encrypt import send_message
from decrypt import get_messages

app = Flask(__name__, static_folder="static")
CORS(app)

# Create data directories if they don't exist
initialize_storage()


# =========================
# Authentication
# =========================

@app.route("/api/register", methods=["POST"])
def register():
    result, status = register_user(request.json)
    return jsonify(result), status


@app.route("/api/login", methods=["POST"])
def login():
    result, status = login_user(request.json)
    return jsonify(result), status


@app.route("/api/users", methods=["GET"])
def users():
    return jsonify({"users": list_users()})


# =========================
# Messaging
# =========================

@app.route("/api/send", methods=["POST"])
def send():
    result, status = send_message(request.json)
    return jsonify(result), status


@app.route("/api/messages", methods=["POST"])
def messages():
    result, status = get_messages(request.json)
    return jsonify(result), status


# =========================
# Static Pages
# =========================

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/login")
def login_page():
    return send_from_directory("static", "login.html")


@app.route("/register")
def register_page():
    return send_from_directory("static", "register.html")


# =========================
# Run Server
# =========================

if __name__ == "__main__":
    app.run(debug=True, port=5000)
