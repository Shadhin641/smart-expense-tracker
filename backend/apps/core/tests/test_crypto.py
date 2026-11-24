import base64
import os

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, override_settings

from apps.core import crypto
from apps.core.money import validate_amount

AAD = crypto.build_aad("table", "field", "user-1", "row-1")


class AesGcmTests(SimpleTestCase):
    def test_round_trip(self):
        self.assertEqual(crypto.decrypt(crypto.encrypt("salary 90000", aad=AAD), aad=AAD), "salary 90000")

    def test_ciphertext_hides_plaintext(self):
        token = crypto.encrypt("90000.00", aad=AAD)
        self.assertNotIn("90000", token)

    def test_nonce_is_unique_per_encryption(self):
        self.assertNotEqual(crypto.encrypt("same", aad=AAD), crypto.encrypt("same", aad=AAD))

    def test_tampering_is_detected(self):
        version, kid, blob = crypto.encrypt("secret", aad=AAD).split(".", 2)
        raw = bytearray(base64.urlsafe_b64decode(blob))
        raw[-1] ^= 0x01
        forged = f"{version}.{kid}.{base64.urlsafe_b64encode(bytes(raw)).decode()}"
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(forged, aad=AAD)

    def test_wrong_context_is_rejected(self):
        token = crypto.encrypt("secret", aad=AAD)
        for other in (
            crypto.build_aad("table", "field", "user-2", "row-1"),  # other user
            crypto.build_aad("table", "field", "user-1", "row-2"),  # other row
            crypto.build_aad("table", "other", "user-1", "row-1"),  # other field
        ):
            with self.assertRaises(crypto.DecryptionError):
                crypto.decrypt(token, aad=other)

    def test_unknown_key_and_garbage_fail_generically(self):
        token = crypto.encrypt("x", aad=AAD)
        for bad in (token.replace(".t1.", ".nope."), "garbage", "", "v9.t1.AAAA", "v1.t1.%%%"):
            with self.assertRaises(crypto.DecryptionError) as ctx:
                crypto.decrypt(bad, aad=AAD)
            self.assertEqual(str(ctx.exception), "Unable to decrypt value.")

    def test_key_rotation(self):
        old, new = os.urandom(32), os.urandom(32)
        ring = {"k1": old, "k2": new}
        with override_settings(FIELD_ENCRYPTION_KEYS=ring, FIELD_ENCRYPTION_ACTIVE_KID="k1"):
            token = crypto.encrypt("rotate me", aad=AAD)
        with override_settings(FIELD_ENCRYPTION_KEYS=ring, FIELD_ENCRYPTION_ACTIVE_KID="k2"):
            self.assertTrue(crypto.needs_rotation(token))
            self.assertEqual(crypto.decrypt(token, aad=AAD), "rotate me")  # old key still readable
            rotated = crypto.rewrap(token, aad=AAD)
            self.assertEqual(crypto.key_id_of(rotated), "k2")
            self.assertFalse(crypto.needs_rotation(rotated))
            self.assertEqual(crypto.decrypt(rotated, aad=AAD), "rotate me")

    def test_aad_rejects_delimiter(self):
        with self.assertRaises(ValueError):
            crypto.build_aad("a|b")


class MoneyTests(SimpleTestCase):
    def test_accepts_valid(self):
        self.assertEqual(str(validate_amount("1234.5")), "1234.50")

    def test_rejects_invalid(self):
        for bad in (1234.56, True, "0", "-5", "abc", "NaN", "Infinity", "1.005", "1000000000.00", None):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                validate_amount(bad)
