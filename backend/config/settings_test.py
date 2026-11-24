"""Settings for automated tests: ephemeral random keys, in-memory SQLite, fast Argon2."""
import base64
import os
import secrets

os.environ.setdefault("DJANGO_SECRET_KEY", secrets.token_urlsafe(64))
os.environ.setdefault("DB_NAME", "test")
os.environ.setdefault("DB_USER", "test")
os.environ.setdefault("DB_PASSWORD", "test")
os.environ.setdefault("FIELD_ENCRYPTION_KEYS", "t1:" + base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("FIELD_ENCRYPTION_ACTIVE_KID", "t1")
os.environ.setdefault("AUDIT_HMAC_KEY", base64.b64encode(os.urandom(48)).decode())

from .settings import *  # noqa: E402,F401,F403

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
SECURE_SSL_REDIRECT = False
ALLOWED_HOSTS = ["testserver", "localhost"]
PASSWORD_HASHERS = ["apps.core.testing.FastArgon2Hasher"]
