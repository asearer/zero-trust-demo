import hmac
import hashlib
import time
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 via werkzeug."""
    return generate_password_hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against the stored hash."""
    return check_password_hash(stored_hash, password)

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

def verify_totp(secret: str, code: str) -> bool:
    """Verifies the TOTP code for a given secret."""
    # In a real app, allow for clock skew (previous/next window)
    expected_code = generate_totp(secret)
    return hmac.compare_digest(code, expected_code)
