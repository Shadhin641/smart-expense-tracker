"""
Django settings for the Smart Expense Tracker.

Every secret and credential is read from the environment (see .env.example).
The application refuses to start if a required secret is missing or malformed.
"""
import base64
import os
import re
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


# --------------------------------------------------------------------------- #
# Environment helpers
# --------------------------------------------------------------------------- #
def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise ImproperlyConfigured(f"Missing required environment variable: {name}")
    return value


def env_bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} must be an integer") from exc


def env_list(name, default=""):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def _decode_key(name, b64_value, *, exact_len=None, min_len=None):
    try:
        key = base64.b64decode(b64_value, validate=True)
    except Exception as exc:
        raise ImproperlyConfigured(f"{name} is not valid base64") from exc
    if exact_len and len(key) != exact_len:
        raise ImproperlyConfigured(f"{name} must decode to exactly {exact_len} bytes")
    if min_len and len(key) < min_len:
        raise ImproperlyConfigured(f"{name} must decode to at least {min_len} bytes")
    return key


def _parse_keyring(raw):
    """'k1:<base64-32-bytes>,k2:<base64-32-bytes>' -> {'k1': b'...', 'k2': b'...'}"""
    keyring = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        kid, sep, b64 = item.partition(":")
        if not sep or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", kid):
            raise ImproperlyConfigured("FIELD_ENCRYPTION_KEYS entries must look like 'kid:base64key'")
        keyring[kid] = _decode_key(f"FIELD_ENCRYPTION_KEYS[{kid}]", b64, exact_len=32)
    if not keyring:
        raise ImproperlyConfigured("FIELD_ENCRYPTION_KEYS contains no keys")
    return keyring


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #
DEBUG = env_bool("DJANGO_DEBUG", False)
SECRET_KEY = env("DJANGO_SECRET_KEY", required=True)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "corsheaders",
    "apps.core",
    "apps.accounts",
    "apps.finance",
    "apps.auditing",
]

# No sessions / messages / admin site: authentication is token based and the
# Django admin would bypass our RBAC and audit rules.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
AUTH_USER_MODEL = "accounts.User"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("DB_NAME", required=True),
        "USER": env("DB_USER", required=True),
        "PASSWORD": env("DB_PASSWORD", required=True),
        "HOST": env("DB_HOST", "localhost"),
        "PORT": env("DB_PORT", "5432"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {"sslmode": env("DB_SSLMODE", "prefer")},
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

# --------------------------------------------------------------------------- #
# Passwords: Argon2id only
# --------------------------------------------------------------------------- #
PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher"]  # type: argon2id
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --------------------------------------------------------------------------- #
# Cryptography (keys live in the environment, never in source control)
# --------------------------------------------------------------------------- #
FIELD_ENCRYPTION_KEYS = _parse_keyring(env("FIELD_ENCRYPTION_KEYS", required=True))
FIELD_ENCRYPTION_ACTIVE_KID = env("FIELD_ENCRYPTION_ACTIVE_KID", required=True)
if FIELD_ENCRYPTION_ACTIVE_KID not in FIELD_ENCRYPTION_KEYS:
    raise ImproperlyConfigured("FIELD_ENCRYPTION_ACTIVE_KID is not present in FIELD_ENCRYPTION_KEYS")
AUDIT_HMAC_KEY = _decode_key("AUDIT_HMAC_KEY", env("AUDIT_HMAC_KEY", required=True), min_len=32)

# --------------------------------------------------------------------------- #
# Security policy
# --------------------------------------------------------------------------- #
LOGIN_MAX_FAILED_ATTEMPTS = env_int("LOGIN_MAX_FAILED_ATTEMPTS", 5)
LOGIN_LOCKOUT_MINUTES = env_int("LOGIN_LOCKOUT_MINUTES", 15)
PASSWORD_RESET_TTL_MINUTES = env_int("PASSWORD_RESET_TTL_MINUTES", 30)
EMAIL_VERIFY_TTL_HOURS = env_int("EMAIL_VERIFY_TTL_HOURS", 24)
# Number of reverse proxies in front of the app that we trust to append to
# X-Forwarded-For. 0 (default) means the header is ignored, so clients cannot
# spoof their IP to evade rate limiting or poison audit logs.
TRUSTED_PROXY_COUNT = env_int("TRUSTED_PROXY_COUNT", 0)

CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", "http://localhost:5173")
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", "http://localhost:5173")

CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_HTTPONLY = False  # SPA must read it for double-submit
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
if not DEBUG:
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", True)
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    if env_bool("BEHIND_TLS_PROXY", False):
        SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --------------------------------------------------------------------------- #
# Django REST Framework
# --------------------------------------------------------------------------- #
REST_FRAMEWORK = {
    # Phase 2 installs the JWT cookie/bearer authentication class here.
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/min",
        "user": "300/min",
        "login": "5/min",
        "register": "10/hour",
        "password_reset": "5/hour",
        "mfa": "10/min",
    },
    "EXCEPTION_HANDLER": "rest_framework.views.exception_handler",
}

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
}
