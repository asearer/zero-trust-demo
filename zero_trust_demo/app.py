"""
app.py

Zero Trust Demo API using Flask, JWT, ABAC, MFA, and refresh token rotation.
Refactored for robustness, security, and industry standards.
"""

import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import jwt
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_talisman import Talisman
from pydantic import BaseModel, Field, ValidationError

# ---------------------------
# Setup & Configuration
# ---------------------------
load_dotenv()  # Load environment variables from .env file

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


# ---------------------------
# Custom Exceptions
# ---------------------------
class AppError(Exception):
    """Base exception for application errors."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class AuthenticationError(AppError):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, status_code=401)


class AuthorizationError(AppError):
    """Raised when authorization fails."""

    def __init__(self, message: str = "Access denied"):
        super().__init__(message, status_code=403)


app = Flask(__name__)

# Security Headers (Talisman)
# Force HTTPS in production, but allow HTTP in dev/test
force_https = os.getenv("FLASK_ENV") == "production"
talisman = Talisman(app, force_https=force_https, content_security_policy=None)

# Configuration Constants
# Configuration Constants
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "SuperSecureSigningKey123":
    logger.warning("Using default or weak SECRET_KEY. Do not do this in production!")
    if not SECRET_KEY:
        # Fallback for now to not break immediate run if env missing
        SECRET_KEY = "SuperSecureSigningKey123"

ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS", 300))
REFRESH_TOKEN_EXPIRE_HOURS = int(os.getenv("REFRESH_TOKEN_EXPIRE_HOURS", 1))

# In-memory store for refresh tokens (Replace with Redis/DB in production)
REFRESH_TOKENS: Dict[str, Dict] = {}

# ---------------------------
# Simulated User Database
# ---------------------------
USER_DB = {
    "alice": {
        "password_hash": hashlib.sha256(b"SuperSecret123").hexdigest(),
        "mfa_secret": "JBSWY3DPEHPK3PXP",
        "role": "admin",
    },
    "bob": {
        "password_hash": hashlib.sha256(b"Password123").hexdigest(),
        "mfa_secret": "KZXW6YPBOI======",
        "role": "user",
    },
}


# ---------------------------
# Pydantic Models
# ---------------------------
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    mfa_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    device: Optional[str] = "unknown"


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)
    device: Optional[str] = "unknown"


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class ResourceAccessRequest(BaseModel):
    action: str = Field(..., pattern=r"^(read|write|delete)$")
    resource: str = Field(..., min_length=1)


# ---------------------------
# Helper Functions
# ---------------------------
def verify_password(username: str, password: str) -> bool:
    """Verifies if the provided password matches the stored hash."""
    if username not in USER_DB:
        return False
    stored_hash = USER_DB[username]["password_hash"]
    input_hash = hashlib.sha256(password.encode()).hexdigest()
    # Use constant time comparison to prevent timing attacks
    # (though hash comparison is fast)
    return hmac.compare_digest(stored_hash, input_hash)


def generate_totp(secret: str, interval: int = 30) -> str:
    """Generates a Time-based One-Time Password (TOTP)."""
    timestep = int(time.time() // interval)
    key = secret.encode()
    msg = timestep.to_bytes(8, "big")
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = (
        int.from_bytes(hmac_hash[offset : offset + 4], "big") & 0x7FFFFFFF
    ) % 1000000
    return str(code).zfill(6)


def verify_totp(username: str, code: str) -> bool:
    """Verifies the TOTP code for a given user."""
    if username not in USER_DB:
        return False
    # In a real app, allow for clock skew (previous/next window)
    expected_code = generate_totp(USER_DB[username]["mfa_secret"])
    return hmac.compare_digest(code, expected_code)


def issue_access_token(username: str, role: str, context: dict) -> str:
    """Issues a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "ip": context.get("ip"),
        "device": context.get("device", "unknown"),
        "iat": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def issue_refresh_token(username: str) -> str:
    """Issues a long-lived opaque refresh token."""
    token = secrets.token_urlsafe(32)
    REFRESH_TOKENS[token] = {
        "username": username,
        "expires_at": datetime.now(timezone.utc)
        + timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS),
    }
    return token


def rotate_refresh_token(old_token: str) -> Optional[str]:
    """Rotates the refresh token (Refresh Token Rotation)."""
    record = REFRESH_TOKENS.get(old_token)
    if not record:
        return None

    if record["expires_at"] < datetime.now(timezone.utc):
        del REFRESH_TOKENS[old_token]  # Cleanup expired
        raise AuthenticationError("Refresh token expired")

    username = record["username"]
    del REFRESH_TOKENS[old_token]  # Revoke old token
    return issue_refresh_token(username)


def verify_jwt(token: str) -> dict:
    """Verifies and decodes the JWT access token."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.warning("JWT Verification Failed: Token expired")
        raise AuthenticationError("Token expired") from None
    except jwt.InvalidTokenError as e:
        logger.warning(f"JWT Verification Failed: {e}")
        raise AuthenticationError("Invalid token") from e


def abac_authorize(claims: dict, action: str, resource: str) -> bool:
    """
    Attribute-Based Access Control (ABAC) logic.
    Decides validation based on User Role, Env Attributes (Time, IP),
    and Resource Attributes.
    """
    role = claims.get("role")
    ip = claims.get("ip")
    device = claims.get("device")

    # Use UTC for consistency
    current_hour = datetime.now(timezone.utc).hour

    logger.debug(
        f"ABAC Check: User={claims.get('sub')}, Role={role}, Action={action}, "
        f"Resource={resource}, Time={current_hour}, IP={ip}"
    )

    # Policy 1: Admin can access anytime, anywhere
    # (simulating broad access, maybe restrict later)
    if role == "admin":
        # Example constraint: Admin only between 6 AM and 10 PM UTC
        allowed = 6 <= current_hour <= 22
        if not allowed:
            logger.info(
                f"Access Denied: Admin {claims.get('sub')} outside working hours."
            )
        return allowed

    # Policy 2: Regular User constraints
    if role == "user":
        # Strict context-aware check
        # Must be: 'read' action, 'data' resource,
        # corporate device (laptop*), corporate IP (10.0.0.*)
        is_read_data = action == "read" and resource == "data"
        is_corp_device = device.startswith("laptop")
        is_corp_ip = ip.startswith("10.0.0.")

        if is_read_data and is_corp_device and is_corp_ip:
            return True
        else:
            logger.info(
                f"Access Denied: User {claims.get('sub')} failed policy check. "
                f"ReadData={is_read_data}, Device={is_corp_device}, IP={is_corp_ip}"
            )
            return False

    return False


# ---------------------------
# Flask Routes
# ---------------------------


@app.errorhandler(ValidationError)
def handle_validation_error(e):
    logger.warning(f"Validation Error: {e.errors()}")
    return jsonify({"error": "Validation Error", "details": e.errors()}), 400


@app.errorhandler(AppError)
def handle_app_error(e):
    logger.warning(f"AppError: {e.message}")
    return jsonify({"error": e.message}), e.status_code


@app.errorhandler(Exception)
def handle_generic_error(e):
    logger.exception("Unexpected Internal Error")
    return jsonify({"error": "Internal Server Error"}), 500


@app.route("/login", methods=["POST"])
def login():
    """Authenticates user with Password and MFA."""
    try:
        # Validate Request Body
        body = LoginRequest(**request.json)
    except ValidationError as e:
        return handle_validation_error(e)

    context = {"ip": request.remote_addr, "device": body.device}

    # 1. Verify Password
    if not verify_password(body.username, body.password):
        logger.warning(
            f"Failed login attempt for user: {body.username} (Invalid Credentials)"
        )
        return jsonify({"error": "Invalid credentials"}), 401

    # 2. Verify MFA
    if not verify_totp(body.username, body.mfa_code):
        logger.warning(f"Failed login attempt for user: {body.username} (Invalid MFA)")
        return jsonify({"error": "Invalid MFA"}), 401

    # 3. Issue Tokens
    role = USER_DB[body.username]["role"]
    access_token = issue_access_token(body.username, role, context)
    refresh_token = issue_refresh_token(body.username)

    logger.info(f"User logged in successfully: {body.username}")
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


@app.route("/refresh", methods=["POST"])
def refresh():
    """Rotates the refresh token and issues a new access token."""
    try:
        body = RefreshRequest(**request.json)
    except ValidationError as e:
        return handle_validation_error(e)

    ip = request.remote_addr

    new_refresh_token = rotate_refresh_token(body.refresh_token)
    if not new_refresh_token:
        logger.warning("Failed refresh attempt: Invalid or expired token.")
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    # Retrieve username from new token record (since old one is gone)
    # Note: In a real DB, we'd look up the user by the new token or a session ID.
    # Here, we need to find who owns this new token.
    username = REFRESH_TOKENS[new_refresh_token]["username"]
    role = USER_DB[username]["role"]

    new_access_token = issue_access_token(
        username, role, {"ip": ip, "device": body.device}
    )

    logger.info(f"Tokens refreshed for user: {username}")
    return jsonify(
        {"access_token": new_access_token, "refresh_token": new_refresh_token}
    )


@app.route("/logout", methods=["POST"])
def logout():
    """Revokes the refresh token."""
    try:
        body = LogoutRequest(**request.json)
    except ValidationError as e:
        return handle_validation_error(e)

    if body.refresh_token in REFRESH_TOKENS:
        del REFRESH_TOKENS[body.refresh_token]
        logger.info("Refresh token revoked.")
        return jsonify({"result": "Refresh token revoked"})

    return jsonify({"error": "Invalid or already revoked token"}), 400


@app.route("/resource", methods=["POST"])
def access_resource():
    """Protected resource that requires valid JWT and ABAC authorization."""
    # 1. Validate JWT
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header.split(" ")[1]
    claims = verify_jwt(token)
    if not claims:
        return jsonify({"error": "Invalid or expired access token"}), 401

    # 2. Validate Request Body
    try:
        body = ResourceAccessRequest(**request.json)
    except ValidationError as e:
        return handle_validation_error(e)

    # 3. ABAC Check
    if abac_authorize(claims, body.action, body.resource):
        logger.info(f"Access GRANTED for user {claims['sub']} to {body.resource}")
        return jsonify(
            {
                "result": "Access Granted",
                "user": claims["sub"],
                "role": claims["role"],
                "action": body.action,
                "resource": body.resource,
            }
        )
    else:
        logger.warning(f"Access DENIED for user {claims['sub']} to {body.resource}")
        return jsonify({"result": "Access Denied"}), 403


if __name__ == "__main__":
    # In production, use gunicorn or similar
    logger.info("Starting Zero Trust Demo API...")
    app.run(debug=True, port=5000)
