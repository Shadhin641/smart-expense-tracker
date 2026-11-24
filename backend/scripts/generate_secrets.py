#!/usr/bin/env python
"""Print fresh secrets for backend/.env (run once per environment; never commit the output)."""
import base64
import secrets

b64 = lambda n: base64.b64encode(secrets.token_bytes(n)).decode()  # noqa: E731

print(f"DJANGO_SECRET_KEY={secrets.token_urlsafe(64)}")
print(f"FIELD_ENCRYPTION_KEYS=k1:{b64(32)}")
print("FIELD_ENCRYPTION_ACTIVE_KID=k1")
print(f"AUDIT_HMAC_KEY={b64(48)}")
print(f"DB_PASSWORD={secrets.token_urlsafe(24)}")
