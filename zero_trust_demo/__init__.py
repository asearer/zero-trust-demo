"""
__init__.py

Makes zero_trust_demo a package.
Exposes the Flask app for easy imports.
"""

from .app import USER_DB as USER_DB
from .app import app as app
from .security import generate_totp as generate_totp
