"""
app.py

Zero Trust Demo API using Flask, JWT, ABAC, MFA, and refresh token rotation.
"""

from flask import Flask, request, jsonify
import hashlib
import hmac
import time
import jwt
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)

# ---------------------------
# Configuration
# ---------------------------
SECRET_KEY = "SuperSecureSigningKey123"  # Use a secure secret in production
REFRESH_TOKENS = {}  # In-memory store for refresh tokens (replace with DB/Redis in prod)

# ---------------------------
# Simulated User Database
# ---------------------------
USER_DB = {
    "alice": {
        "password_hash": hashlib.sha256(b"SuperSecret123").hexdigest(),
        "mfa_secret": "JBSWY3DPEHPK3PXP",
        "role": "admin"
    },
    "bob": {
        "password_hash": hashlib.sha256(b"Password123").hexdigest(),
        "mfa_secret": "KZXW6YPBOI======",
        "role": "user"
    }
}

# ---------------------------
# Helper Functions
# ---------------------------
def verify_password(username: str, password: str) -> bool:
    stored_hash = USER_DB[username]["password_hash"]
    return stored_hash == hashlib.sha256(password.encode()).hexdigest()


def generate_totp(secret: str, interval: int = 30) -> str:
    timestep = int(time.time() // interval)
    key = secret.encode()
    msg = timestep.to_bytes(8, "big")
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = (int.from_bytes(hmac_hash[offset:offset+4], "big") & 0x7FFFFFFF) % 1000000
    return str(code).zfill(6)


def verify_totp(username: str, code: str) -> bool:
    return code == generate_totp(USER_DB[username]["mfa_secret"])


def issue_access_token(username: str, role: str, context: dict) -> str:
    payload = {
        "sub": username,
        "role": role,
        "ip": context.get("ip"),
        "device": context.get("device", "unknown"),
        "iat": int(time.time()),
        "exp": int(time.time()) + 300  # 5 minutes
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def issue_refresh_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    REFRESH_TOKENS[token] = {
        "username": username,
        "expires_at": datetime.utcnow() + timedelta(hours=1)
    }
    return token


def rotate_refresh_token(old_token: str) -> str | None:
    record = REFRESH_TOKENS.get(old_token)
    if not record or record["expires_at"] < datetime.utcnow():
        return None
    username = record["username"]
    del REFRESH_TOKENS[old_token]
    return issue_refresh_token(username)


def verify_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def abac_authorize(claims: dict, action: str, resource: str) -> bool:
    role = claims.get("role")
    ip = claims.get("ip")
    device = claims.get("device")
    current_hour = datetime.utcnow().hour

    if role == "admin":
        return 6 <= current_hour <= 22

    if role == "user":
        return (
            action == "read"
            and resource == "data"
            and device.startswith("laptop")
            and ip.startswith("10.0.0.")
        )

    return False

# ---------------------------
# Flask Routes
# ---------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    mfa_code = data.get("mfa_code")
    context = {"ip": request.remote_addr, "device": data.get("device", "unknown")}

    if username not in USER_DB or not verify_password(username, password):
        return jsonify({"error": "Invalid credentials"}), 401
    if not verify_totp(username, mfa_code):
        return jsonify({"error": "Invalid MFA"}), 401

    access_token = issue_access_token(username, USER_DB[username]["role"], context)
    refresh_token = issue_refresh_token(username)
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json
    old_refresh_token = data.get("refresh_token")
    device = data.get("device", "unknown")
    ip = request.remote_addr

    new_refresh_token = rotate_refresh_token(old_refresh_token)
    if not new_refresh_token:
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    username = REFRESH_TOKENS[new_refresh_token]["username"]
    role = USER_DB[username]["role"]
    new_access_token = issue_access_token(username, role, {"ip": ip, "device": device})
    return jsonify({"access_token": new_access_token, "refresh_token": new_refresh_token})


@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    refresh_token = data.get("refresh_token")
    if not refresh_token or refresh_token not in REFRESH_TOKENS:
        return jsonify({"error": "Invalid or already revoked token"}), 400
    del REFRESH_TOKENS[refresh_token]
    return jsonify({"result": "Refresh token revoked"})


@app.route("/resource", methods=["POST"])
def access_resource():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header.split(" ")[1]
    claims = verify_jwt(token)
    if not claims:
        return jsonify({"error": "Invalid or expired access token"}), 401

    data = request.json
    action = data.get("action")
    resource = data.get("resource")

    if abac_authorize(claims, action, resource):
        return jsonify({
            "result": "Access Granted",
            "user": claims["sub"],
            "role": claims["role"],
            "action": action,
            "resource": resource
        })
    else:
        return jsonify({"result": "Access Denied"}), 403


if __name__ == "__main__":
    app.run(debug=True)
