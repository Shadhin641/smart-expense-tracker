"""Identity, authentication-state and session models."""
import hashlib
import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import check_password, make_password
from django.db import models, transaction
from django.utils import timezone

from apps.core.models import EncryptedRecordMixin


class Role(models.TextChoices):
    ADMIN = "admin", "Admin"
    USER = "user", "Normal user"


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create(self, email, password, **extra):
        if not email:
            raise ValueError("Email is required")
        if not password:
            raise ValueError("Password is required")
        user = self.model(email=self.normalize_email(email).lower(), **extra)
        user.set_password(password)  # Argon2id
        user.save(using=self._db)
        UserProfile.objects.create(user=user)
        return user

    def create_user(self, email, password=None, **extra):
        extra.setdefault("role", Role.USER)
        return self._create(email, password, **extra)

    def create_admin(self, email, password=None, **extra):
        extra.update(role=Role.ADMIN, is_email_verified=True, email_verified_at=timezone.now())
        return self._create(email, password, **extra)


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=254, unique=True)  # always stored lowercase
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.USER)
    is_active = models.BooleanField(default=True)
    is_suspended = models.BooleanField(default=False)
    suspended_at = models.DateTimeField(null=True, blank=True)
    suspension_reason = models.CharField(max_length=255, blank=True)
    is_email_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    failed_login_count = models.PositiveIntegerField(default=0)
    last_failed_login_at = models.DateTimeField(null=True, blank=True)
    locked_until = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(role__in=["admin", "user"]), name="user_role_valid"),
        ]
        indexes = [models.Index(fields=["role", "is_active"], name="user_role_active_idx")]

    def save(self, *args, **kwargs):
        self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    @property
    def is_locked(self):
        return bool(self.locked_until and self.locked_until > timezone.now())

    @property
    def can_authenticate(self):
        return self.is_active and not self.is_suspended and not self.is_locked

    def __str__(self):
        return self.email


class UserProfile(models.Model):
    class Theme(models.TextChoices):
        LIGHT = "light"
        DARK = "dark"
        SYSTEM = "system"

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    full_name = models.CharField(max_length=100, blank=True)
    currency = models.CharField(max_length=3, default="BDT")
    timezone = models.CharField(max_length=64, default="Asia/Dhaka")
    theme = models.CharField(max_length=6, choices=Theme.choices, default=Theme.SYSTEM)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class MFASettings(EncryptedRecordMixin, models.Model):
    """TOTP configuration. The shared secret is AES-256-GCM encrypted at rest."""

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True, related_name="mfa")
    secret_enc = models.TextField(blank=True)
    is_enabled = models.BooleanField(default=False)  # becomes True only after the first OTP is verified
    confirmed_at = models.DateTimeField(null=True, blank=True)
    last_used_step = models.PositiveBigIntegerField(null=True, blank=True)  # blocks TOTP replay
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def secret(self):
        return self._get_encrypted("secret")

    @secret.setter
    def secret(self, value):
        self._set_encrypted("secret", value)


_BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I


def _normalize_backup_code(code: str) -> str:
    return code.replace("-", "").replace(" ", "").upper()


class BackupCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="backup_codes")
    code_hash = models.CharField(max_length=255)  # Argon2id hash; the raw code is shown once
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["user", "used_at"], name="backupcode_user_used_idx")]

    @classmethod
    def generate_for(cls, user, count=10):
        """Replace all codes for `user`; return the raw codes (display once, never stored)."""
        raw_codes = []
        with transaction.atomic():
            cls.objects.filter(user=user).delete()
            for _ in range(count):
                raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(8))
                cls.objects.create(user=user, code_hash=make_password(raw))
                raw_codes.append(f"{raw[:4]}-{raw[4:]}")
        return raw_codes

    @classmethod
    def consume(cls, user, submitted: str) -> bool:
        normalized = _normalize_backup_code(submitted)
        for code in cls.objects.filter(user=user, used_at__isnull=True):
            if check_password(normalized, code.code_hash):
                updated = cls.objects.filter(pk=code.pk, used_at__isnull=True).update(used_at=timezone.now())
                return updated == 1
        return False


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SingleUseToken(models.Model):
    """Random 256-bit token; only its SHA-256 is stored, so a DB leak yields no usable tokens."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="%(class)ss")
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True

    @classmethod
    def issue(cls, user, ttl: timedelta, **extra):
        """Invalidate earlier unused tokens, then return (instance, raw_token)."""
        now = timezone.now()
        raw = secrets.token_urlsafe(32)
        with transaction.atomic():
            cls.objects.filter(user=user, used_at__isnull=True).update(used_at=now)
            obj = cls.objects.create(user=user, token_hash=hash_token(raw), expires_at=now + ttl, **extra)
        return obj, raw

    @classmethod
    def consume(cls, raw: str):
        """Atomically mark a valid token as used and return it; None if invalid, expired or reused."""
        digest, now = hash_token(raw), timezone.now()
        updated = cls.objects.filter(token_hash=digest, used_at__isnull=True, expires_at__gt=now).update(used_at=now)
        if updated != 1:
            return None
        return cls.objects.select_related("user").get(token_hash=digest)


class PasswordResetToken(SingleUseToken):
    requested_ip = models.CharField(max_length=45, blank=True)


class EmailVerificationToken(SingleUseToken):
    pass


class UserSession(models.Model):
    """One row per login. `id` is the `sid` claim in the JWTs; refresh tokens rotate `current_jti`."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sessions")
    current_jti = models.CharField(max_length=64, blank=True)
    ip_address = models.CharField(max_length=45, blank=True)
    user_agent = models.CharField(max_length=400, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=50, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "revoked_at"], name="session_user_revoked_idx"),
            models.Index(fields=["expires_at"], name="session_expires_idx"),
        ]

    @property
    def is_active(self):
        return self.revoked_at is None and self.expires_at > timezone.now()

    def revoke(self, reason: str):
        if self.revoked_at is None:
            self.revoked_at, self.revoked_reason = timezone.now(), reason
            self.save(update_fields=["revoked_at", "revoked_reason"])


class LoginAttempt(models.Model):
    class Failure(models.TextChoices):
        BAD_PASSWORD = "bad_password"
        UNKNOWN_USER = "unknown_user"
        ACCOUNT_LOCKED = "account_locked"
        ACCOUNT_SUSPENDED = "account_suspended"
        EMAIL_UNVERIFIED = "email_unverified"
        MFA_FAILED = "mfa_failed"
        RATE_LIMITED = "rate_limited"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="login_attempts")
    email_attempted = models.CharField(max_length=254)
    succeeded = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=20, choices=Failure.choices, blank=True)
    ip_address = models.CharField(max_length=45, blank=True)
    user_agent = models.CharField(max_length=400, blank=True)
    is_suspicious = models.BooleanField(default=False)
    suspicion_reasons = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=["user", "-created_at"], name="login_user_time_idx"),
            models.Index(fields=["ip_address", "-created_at"], name="login_ip_time_idx"),
            models.Index(fields=["email_attempted", "-created_at"], name="login_email_time_idx"),
            models.Index(fields=["is_suspicious", "-created_at"], name="login_susp_time_idx"),
        ]
