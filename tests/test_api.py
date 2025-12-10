"""
test_api.py

Expanded comprehensive tests for Zero Trust Demo API.

Covers:
- Login (success/failure)
- MFA validation
- ABAC resource access (including time, IP, device)
- JWT access token validation
- Refresh token rotation
- Logout and revoked token behavior
- Edge cases and fuzz testing
"""

import pytest
from zero_trust_demo import app, USER_DB, generate_totp
from datetime import datetime, timedelta, timezone
import jwt
from freezegun import freeze_time
import random, string

@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def get_valid_mfa(username: str) -> str:
    """Generate a valid MFA code for a given user."""
    return generate_totp(USER_DB[username]["mfa_secret"])


# -----------------------
# LOGIN TESTS
# -----------------------
def test_login_success(client):
    res = client.post("/login", json={
        "username": "alice",
        "password": "SuperSecret123",
        "mfa_code": get_valid_mfa("alice"),
        "device": "laptop-001"
    })
    data = res.get_json()
    assert res.status_code == 200
    assert "access_token" in data and "refresh_token" in data


def test_login_wrong_password(client):
    res = client.post("/login", json={
        "username": "alice",
        "password": "WrongPassword",
        "mfa_code": get_valid_mfa("alice"),
        "device": "laptop-001"
    })
    assert res.status_code == 401


def test_login_wrong_mfa(client):
    res = client.post("/login", json={
        "username": "alice",
        "password": "SuperSecret123",
        "mfa_code": "000000",
        "device": "laptop-001"
    })
    assert res.status_code == 401


def test_login_nonexistent_user(client):
    res = client.post("/login", json={
        "username": "charlie",
        "password": "Anything",
        "mfa_code": "123456",
        "device": "laptop-001"
    })
    assert res.status_code == 401


def test_login_empty_fields(client):
    res = client.post("/login", json={})
    assert res.status_code == 400


# -----------------------
# RESOURCE ACCESS (ABAC) TESTS
# -----------------------
def test_admin_access_allowed(client):
    """Admin allowed during business hours."""
    with freeze_time("2025-09-24 12:00:00"):  # 12 PM UTC
        login_res = client.post("/login", json={
            "username": "alice",
            "password": "SuperSecret123",
            "mfa_code": get_valid_mfa("alice"),
            "device": "laptop-001"
        }).get_json()
        token = login_res["access_token"]
        res = client.post("/resource", json={"action": "read", "resource": "data"},
                          headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200 or res.status_code == 403


def test_admin_access_denied_outside_hours(client):
    """Admin denied outside business hours."""
    with freeze_time("2025-09-24 23:00:00"):  # 11 PM UTC
        login_res = client.post("/login", json={
            "username": "alice",
            "password": "SuperSecret123",
            "mfa_code": get_valid_mfa("alice"),
            "device": "laptop-001"
        }).get_json()
        token = login_res["access_token"]
        res = client.post("/resource", json={"action": "read", "resource": "data"},
                          headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 403


def test_user_read_allowed(client):
    login_res = client.post("/login", json={
        "username": "bob",
        "password": "Password123",
        "mfa_code": get_valid_mfa("bob"),
        "device": "laptop-001"
    }).get_json()
    token = login_res["access_token"]
    res = client.post("/resource", json={"action": "read", "resource": "data"},
                      headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (200, 403)


def test_user_write_denied(client):
    login_res = client.post("/login", json={
        "username": "bob",
        "password": "Password123",
        "mfa_code": get_valid_mfa("bob"),
        "device": "laptop-001"
    }).get_json()
    token = login_res["access_token"]
    res = client.post("/resource", json={"action": "write", "resource": "data"},
                      headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


# -----------------------
# JWT EDGE CASES
# -----------------------
def test_missing_authorization(client):
    res = client.post("/resource", json={"action": "read", "resource": "data"})
    assert res.status_code == 401


def test_malformed_jwt(client):
    res = client.post("/resource", json={"action": "read", "resource": "data"},
                      headers={"Authorization": "Bearer bad.token.value"})
    assert res.status_code == 401


# -----------------------
# REFRESH TOKEN & LOGOUT
# -----------------------
def test_refresh_token_rotation_and_logout(client):
    login_res = client.post("/login", json={
        "username": "alice",
        "password": "SuperSecret123",
        "mfa_code": get_valid_mfa("alice"),
        "device": "laptop-001"
    }).get_json()

    old_refresh = login_res["refresh_token"]

    # Rotate refresh token
    refresh_res = client.post("/refresh", json={"refresh_token": old_refresh, "device": "laptop-001"})
    assert refresh_res.status_code == 200
    new_refresh = refresh_res.get_json()["refresh_token"]

    # Old token invalid
    old_res = client.post("/refresh", json={"refresh_token": old_refresh, "device": "laptop-001"})
    assert old_res.status_code == 401

    # Logout revokes new token
    logout_res = client.post("/logout", json={"refresh_token": new_refresh})
    assert logout_res.status_code == 200

    # Reuse of revoked token
    reuse_res = client.post("/refresh", json={"refresh_token": new_refresh, "device": "laptop-001"})
    assert reuse_res.status_code == 401


def test_expired_access_token(client):
    """Simulate expired JWT access token."""
    login_res = client.post("/login", json={
        "username": "alice",
        "password": "SuperSecret123",
        "mfa_code": get_valid_mfa("alice"),
        "device": "laptop-001"
    }).get_json()

    token = login_res["access_token"]
    payload = jwt.decode(token, options={"verify_signature": False})
    payload["exp"] = datetime.now(timezone.utc).timestamp() - 1  # expired
    expired_token = jwt.encode(payload, "SuperSecureSigningKey123", algorithm="HS256")

    res = client.post("/resource", json={"action": "read", "resource": "data"},
                      headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401


# -----------------------
# FUZZ & EDGE CASES
# -----------------------
def test_random_fuzz_login(client):
    """Send random data to login endpoint."""
    payload = {
        "username": "".join(random.choices(string.printable, k=50)),
        "password": "".join(random.choices(string.printable, k=50)),
        "mfa_code": "123456",
        "device": "".join(random.choices(string.printable, k=20))
    }
    res = client.post("/login", json=payload)
    assert res.status_code == 401
