"""
AES-256-GCM field encryption.

Token format:  v1.<key-id>.<urlsafe-base64(nonce || ciphertext || tag)>

* 256-bit keys come from the environment (FIELD_ENCRYPTION_KEYS), never from code.
* A fresh random 96-bit nonce is generated for every encryption.
* The key id in the token enables key rotation: old tokens stay decryptable
  while new writes use FIELD_ENCRYPTION_ACTIVE_KID; `rewrap` migrates a token.
* Associated data (AAD) binds each ciphertext to its context (table, field,
  owner, row). Copying a ciphertext into another row, field or user makes
  authentication fail, which defeats ciphertext-swapping attacks.
* All failures raise DecryptionError with a deliberately generic message.
"""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

TOKEN_VERSION = "v1"
NONCE_SIZE = 12


class DecryptionError(Exception):
    """Raised for any decryption failure (tampering, wrong context, unknown key...)."""


def build_aad(*parts: str) -> bytes:
    for part in parts:
        if "|" in part:
            raise ValueError("AAD parts must not contain '|'")
    return "|".join(parts).encode("utf-8")


def _active():
    keys = settings.FIELD_ENCRYPTION_KEYS
    kid = settings.FIELD_ENCRYPTION_ACTIVE_KID
    if kid not in keys:
        raise ImproperlyConfigured("Active encryption key id is not in the keyring")
    return kid, keys[kid]


def encrypt(plaintext, *, aad: bytes) -> str:
    kid, key = _active()
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
    nonce = os.urandom(NONCE_SIZE)
    sealed = AESGCM(key).encrypt(nonce, data, aad)
    return f"{TOKEN_VERSION}.{kid}.{base64.urlsafe_b64encode(nonce + sealed).decode('ascii')}"


def decrypt(token: str, *, aad: bytes) -> str:
    try:
        version, kid, blob = token.split(".", 2)
        if version != TOKEN_VERSION:
            raise ValueError("unsupported version")
        key = settings.FIELD_ENCRYPTION_KEYS[kid]
        raw = base64.urlsafe_b64decode(blob.encode("ascii"))
        nonce, sealed = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
        return AESGCM(key).decrypt(nonce, sealed, aad).decode("utf-8")
    except (ValueError, KeyError, InvalidTag, TypeError, AttributeError):
        raise DecryptionError("Unable to decrypt value.") from None


def key_id_of(token: str) -> str:
    try:
        return token.split(".", 2)[1]
    except (IndexError, AttributeError):
        raise DecryptionError("Unable to decrypt value.") from None


def needs_rotation(token: str) -> bool:
    return key_id_of(token) != settings.FIELD_ENCRYPTION_ACTIVE_KID


def rewrap(token: str, *, aad: bytes) -> str:
    """Decrypt with whichever key sealed the token and re-encrypt with the active key."""
    return encrypt(decrypt(token, aad=aad), aad=aad)
