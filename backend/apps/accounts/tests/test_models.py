from datetime import timedelta

from django.db import IntegrityError, connection, transaction
from django.test import TestCase
from django.utils import timezone

from apps.accounts.models import BackupCode, EmailVerificationToken, MFASettings, PasswordResetToken, Role, User, UserSession


class UserTests(TestCase):
    def test_password_is_argon2id_and_never_plaintext(self):
        user = User.objects.create_user("Alice@Example.COM", "correct horse battery staple")
        self.assertTrue(user.password.startswith("argon2$argon2id$"))
        self.assertNotIn("correct horse", user.password)
        self.assertTrue(user.check_password("correct horse battery staple"))
        self.assertFalse(user.check_password("wrong"))

    def test_email_normalised_and_unique_case_insensitively(self):
        User.objects.create_user("Bob@Example.com", "pw-pw-pw-pw-pw")
        self.assertEqual(User.objects.get().email, "bob@example.com")
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create_user("BOB@example.com", "pw-pw-pw-pw-pw")

    def test_roles_and_profile(self):
        user = User.objects.create_user("u@example.com", "pw-pw-pw-pw-pw")
        admin = User.objects.create_admin("a@example.com", "pw-pw-pw-pw-pw")
        self.assertEqual(user.role, Role.USER)
        self.assertFalse(user.is_admin)
        self.assertTrue(admin.is_admin and admin.is_email_verified)
        self.assertEqual((user.profile.currency, user.profile.timezone), ("BDT", "Asia/Dhaka"))

    def test_can_authenticate_respects_lockout_and_suspension(self):
        user = User.objects.create_user("l@example.com", "pw-pw-pw-pw-pw")
        self.assertTrue(user.can_authenticate)
        user.locked_until = timezone.now() + timedelta(minutes=5)
        self.assertTrue(user.is_locked and not user.can_authenticate)
        user.locked_until = timezone.now() - timedelta(minutes=1)
        self.assertTrue(user.can_authenticate)
        user.is_suspended = True
        self.assertFalse(user.can_authenticate)


class TokenTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("t@example.com", "pw-pw-pw-pw-pw")

    def test_only_hash_is_stored(self):
        obj, raw = PasswordResetToken.issue(self.user, timedelta(minutes=30))
        self.assertNotEqual(obj.token_hash, raw)
        self.assertEqual(len(obj.token_hash), 64)
        with connection.cursor() as cur:
            cur.execute("SELECT token_hash FROM accounts_passwordresettoken")
            self.assertNotIn(raw, [r[0] for r in cur.fetchall()])

    def test_single_use(self):
        _, raw = PasswordResetToken.issue(self.user, timedelta(minutes=30))
        self.assertEqual(PasswordResetToken.consume(raw).user, self.user)
        self.assertIsNone(PasswordResetToken.consume(raw))  # replay fails

    def test_expired_and_unknown_rejected(self):
        _, raw = EmailVerificationToken.issue(self.user, timedelta(seconds=-1))
        self.assertIsNone(EmailVerificationToken.consume(raw))
        self.assertIsNone(EmailVerificationToken.consume("not-a-token"))

    def test_new_token_invalidates_previous(self):
        _, first = PasswordResetToken.issue(self.user, timedelta(minutes=30))
        _, second = PasswordResetToken.issue(self.user, timedelta(minutes=30))
        self.assertIsNone(PasswordResetToken.consume(first))
        self.assertIsNotNone(PasswordResetToken.consume(second))


class MfaTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("m@example.com", "pw-pw-pw-pw-pw")

    def test_totp_secret_encrypted_at_rest(self):
        secret = "JBSWY3DPEHPK3PXP"
        mfa = MFASettings(user=self.user)
        mfa.secret = secret
        mfa.save()
        with connection.cursor() as cur:
            cur.execute("SELECT secret_enc FROM accounts_mfasettings")
            stored = cur.fetchone()[0]
        self.assertNotIn(secret, stored)
        self.assertEqual(MFASettings.objects.get(pk=self.user.pk).secret, secret)

    def test_backup_codes_hashed_and_single_use(self):
        codes = BackupCode.generate_for(self.user)
        self.assertEqual(len(set(codes)), 10)
        for stored in BackupCode.objects.values_list("code_hash", flat=True):
            self.assertTrue(stored.startswith("argon2$"))
            self.assertFalse(any(c.replace("-", "") in stored for c in codes))
        self.assertTrue(BackupCode.consume(self.user, codes[0].lower()))  # case/format tolerant
        self.assertFalse(BackupCode.consume(self.user, codes[0]))  # single use
        self.assertFalse(BackupCode.consume(self.user, "AAAA-AAAA"))

    def test_regenerating_replaces_old_codes(self):
        old = BackupCode.generate_for(self.user)
        BackupCode.generate_for(self.user)
        self.assertFalse(BackupCode.consume(self.user, old[0]))


class SessionTests(TestCase):
    def test_revoke(self):
        user = User.objects.create_user("s@example.com", "pw-pw-pw-pw-pw")
        session = UserSession.objects.create(user=user, expires_at=timezone.now() + timedelta(days=7))
        self.assertTrue(session.is_active)
        session.revoke("logout")
        session.refresh_from_db()
        self.assertFalse(session.is_active)
        self.assertEqual(session.revoked_reason, "logout")
