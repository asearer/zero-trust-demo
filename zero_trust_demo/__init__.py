"""
__init__.py

Makes zero_trust_demo a package.
Exposes the Flask app for easy imports.
"""

from .app import app, USER_DB, generate_totp
