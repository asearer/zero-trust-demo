import pytest
from freezegun import freeze_time

from zero_trust_demo.app import (
    USER_DB,
    AuthenticationError,
    abac_authorize,
    generate_totp,
    issue_access_token,
    verify_jwt,
    verify_password,
    verify_totp,
)


# ---------------------------
# Password & MFA Tests
# ---------------------------
def test_verify_password_success():
    assert verify_password("alice", "SuperSecret123") is True


def test_verify_password_failure():
    assert verify_password("alice", "WrongPassword") is False
    assert verify_password("unknown_user", "Anything") is False


def test_totp_generation_and_verification():
    secret = USER_DB["alice"]["mfa_secret"]
    code = generate_totp(secret)
    assert verify_totp("alice", code) is True


def test_totp_verification_failure():
    assert verify_totp("alice", "000000") is False
    assert verify_totp("unknown_user", "123456") is False


# ---------------------------
# Token Tests
# ---------------------------
def test_issue_access_token_structure():
    token = issue_access_token(
        "alice", "admin", {"ip": "127.0.0.1", "device": "test-device"}
    )
    assert isinstance(token, str)
    claims = verify_jwt(token)
    assert claims["sub"] == "alice"
    assert claims["role"] == "admin"
    assert claims["ip"] == "127.0.0.1"


def test_verify_jwt_expired():
    # Issue a token that is already expired
    with freeze_time("2020-01-01 12:00:00"):
        token = issue_access_token("alice", "admin", {})

    with freeze_time("2020-01-01 13:00:00"):
        with pytest.raises(AuthenticationError, match="Token expired"):
            verify_jwt(token)


def test_verify_jwt_invalid():
    with pytest.raises(AuthenticationError, match="Invalid token"):
        verify_jwt("invalid.token.structure")


# ---------------------------
# ABAC Tests
# ---------------------------
def test_abac_admin_allowed_in_hours():
    claims = {"role": "admin", "sub": "alice"}
    with freeze_time("2025-01-01 12:00:00"):  # 12 PM UTC
        assert abac_authorize(claims, "read", "data") is True


def test_abac_admin_denied_off_hours():
    claims = {"role": "admin", "sub": "alice"}
    with freeze_time("2025-01-01 04:00:00"):  # 4 AM UTC
        assert abac_authorize(claims, "read", "data") is False


def test_abac_user_success():
    claims = {"role": "user", "sub": "bob", "ip": "10.0.0.5", "device": "laptop-123"}
    assert abac_authorize(claims, "read", "data") is True


def test_abac_user_failure_wrong_ip():
    claims = {"role": "user", "sub": "bob", "ip": "192.168.1.1", "device": "laptop-123"}
    assert abac_authorize(claims, "read", "data") is False


def test_abac_user_failure_wrong_device():
    claims = {"role": "user", "sub": "bob", "ip": "10.0.0.5", "device": "phone-123"}
    assert abac_authorize(claims, "read", "data") is False
