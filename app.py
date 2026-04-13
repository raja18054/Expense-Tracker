# ============================================================
# Flask REST API with JWT Authentication
# Project: User Authentication API
# Description: A secure REST API that allows users to register,
#              login, generate JWT tokens, and access protected routes.
# ============================================================

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os
import re

# ─── App Initialization ───────────────────────────────────────
app = Flask(__name__, static_folder="static")
CORS(app)  # Enable CORS for frontend

# ─── Configuration ────────────────────────────────────────────
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# JWT secret key – in production, set via environment variable
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "change-this-super-secret-key-in-production")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

# ─── Extensions ───────────────────────────────────────────────
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ─── Database Model ───────────────────────────────────────────
class User(db.Model):
    """User model – stores id, username, and hashed password."""
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def to_dict(self):
        """Return a safe dict (never expose password)."""
        return {"id": self.id, "username": self.username}

# ─── Helpers ──────────────────────────────────────────────────
def is_valid_username(username: str) -> bool:
    """Username: 3–30 chars, alphanumeric + underscores only."""
    return bool(re.match(r"^[a-zA-Z0-9_]{3,30}$", username))

def is_valid_password(password: str) -> bool:
    """Password: minimum 6 characters."""
    return len(password) >= 6

# ─── Serve Frontend ───────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    """Serve the frontend UI."""
    return send_from_directory("static", "index.html")

# ─── Routes ───────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Both 'username' and 'password' are required."}), 400

    if not is_valid_username(username):
        return jsonify({"error": "Username must be 3–30 chars (letters, digits, underscores only)."}), 422

    if not is_valid_password(password):
        return jsonify({"error": "Password must be at least 6 characters."}), 422

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken."}), 409

    hashed_pw = generate_password_hash(password)
    new_user  = User(username=username, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "User registered successfully.",
        "user": new_user.to_dict()
    }), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Both 'username' and 'password' are required."}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid username or password."}), 401

    access_token = create_access_token(identity=str(user.id))

    return jsonify({
        "message":      "Login successful.",
        "access_token": access_token,
        "token_type":   "Bearer",
        "expires_in":   "1 hour"
    }), 200


@app.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))

    if not user:
        return jsonify({"error": "User not found."}), 404

    return jsonify({
        "message": "Access granted.",
        "user":    user.to_dict()
    }), 200


# ─── JWT Error Handlers ───────────────────────────────────────
@jwt.unauthorized_loader
def missing_token_callback(reason):
    return jsonify({"error": "Authorization token is missing.", "detail": reason}), 401

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({"error": "Token is invalid.", "detail": reason}), 422

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired. Please log in again."}), 401


# ─── Database Initializer & Entry Point ───────────────────────
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=False)
