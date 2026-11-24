"""Shared model building blocks."""
from django.db import models

from . import crypto


class OwnedQuerySet(models.QuerySet):
    """Every query on user-owned data should start with `.for_user(request.user)`."""

    def for_user(self, user):
        return self.filter(user_id=user.pk)


class EncryptedRecordMixin:
    """
    Helpers for models that keep sensitive values in `<name>_enc` text columns.

    The ciphertext is bound (via AAD) to the table, the field name, the owning
    user and the row's primary key, so it cannot be moved to another row/user.
    Requires `user_id` and a pk that is known before the first save (UUID).
    """

    def _aad(self, field: str) -> bytes:
        return crypto.build_aad(self._meta.db_table, field, str(self.user_id), str(self.pk))

    def _get_encrypted(self, field: str) -> str:
        token = getattr(self, f"{field}_enc")
        return crypto.decrypt(token, aad=self._aad(field)) if token else ""

    def _set_encrypted(self, field: str, value) -> None:
        setattr(self, f"{field}_enc", crypto.encrypt(value, aad=self._aad(field)) if value not in (None, "") else "")
