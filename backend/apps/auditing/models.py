"""Audit trail (append-only, hash-chained), security events and user notifications."""
import uuid  # noqa: F401

from django.conf import settings
from django.db import models
from django.utils import timezone


class ImmutableRecordError(Exception):
    """Audit records can be created but never modified or deleted."""


class Severity(models.TextChoices):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ImmutableRecordError("Audit logs are append-only.")

    def delete(self):
        raise ImmutableRecordError("Audit logs are append-only.")

    def bulk_update(self, *args, **kwargs):
        raise ImmutableRecordError("Audit logs are append-only.")

    def bulk_create(self, *args, **kwargs):
        raise ImmutableRecordError("Use auditing.services.record_audit() so the hash chain stays intact.")


class AuditLog(models.Model):
    class Action(models.TextChoices):
        LOGIN_SUCCESS = "login_success"
        LOGIN_FAILED = "login_failed"
        LOGOUT = "logout"
        EMAIL_VERIFIED = "email_verified"
        PASSWORD_CHANGED = "password_changed"
        PASSWORD_RESET_REQUESTED = "password_reset_requested"
        PASSWORD_RESET_COMPLETED = "password_reset_completed"
        MFA_ENABLED = "mfa_enabled"
        MFA_DISABLED = "mfa_disabled"
        BACKUP_CODES_REGENERATED = "backup_codes_regenerated"
        SESSION_REVOKED = "session_revoked"
        TRANSACTION_CREATED = "transaction_created"
        TRANSACTION_UPDATED = "transaction_updated"
        TRANSACTION_DELETED = "transaction_deleted"
        BUDGET_CREATED = "budget_created"
        BUDGET_UPDATED = "budget_updated"
        BUDGET_DELETED = "budget_deleted"
        ACCOUNT_SETTINGS_CHANGED = "account_settings_changed"
        ACCOUNT_SUSPENDED = "account_suspended"
        ACCOUNT_REACTIVATED = "account_reactivated"
        REPORT_EXPORTED = "report_exported"

    # No FK to users on purpose: the trail must survive account deletion and must
    # never trigger an UPDATE/DELETE on audit rows through referential actions.
    actor_id = models.UUIDField(null=True, blank=True, db_index=True)
    actor_email = models.CharField(max_length=254, blank=True)
    action = models.CharField(max_length=40, choices=Action.choices, db_index=True)
    target_type = models.CharField(max_length=40, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    ip_address = models.CharField(max_length=45, blank=True)
    user_agent = models.CharField(max_length=400, blank=True)
    details = models.JSONField(default=dict, blank=True)  # ids / field names only, never financial values
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    prev_hash = models.CharField(max_length=64, editable=False)
    entry_hash = models.CharField(max_length=64, unique=True, editable=False)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["id"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ImmutableRecordError("Audit logs are append-only.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ImmutableRecordError("Audit logs are append-only.")


class SecurityEvent(models.Model):
    class EventType(models.TextChoices):
        BRUTE_FORCE_DETECTED = "brute_force_detected"
        ACCOUNT_LOCKED = "account_locked"
        SUSPICIOUS_LOGIN = "suspicious_login"
        NEW_DEVICE_LOGIN = "new_device_login"
        MFA_FAILED = "mfa_failed"
        REFRESH_TOKEN_REUSE = "refresh_token_reuse"
        PASSWORD_RESET_REQUESTED = "password_reset_requested"
        ACCESS_DENIED = "access_denied"
        RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
        ADMIN_ACTION = "admin_action"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="security_events")
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    severity = models.CharField(max_length=8, choices=Severity.choices, default=Severity.INFO)
    ip_address = models.CharField(max_length=45, blank=True)
    user_agent = models.CharField(max_length=400, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["-created_at"], name="secevent_time_idx"),
            models.Index(fields=["event_type", "-created_at"], name="secevent_type_time_idx"),
            models.Index(fields=["severity", "acknowledged_at"], name="secevent_sev_ack_idx"),
        ]


class Notification(models.Model):
    class Kind(models.TextChoices):
        BUDGET_WARNING = "budget_warning"
        BUDGET_EXCEEDED = "budget_exceeded"
        SUSPICIOUS_LOGIN = "suspicious_login"
        ACCOUNT_LOCKED = "account_locked"
        SECURITY_ALERT = "security_alert"
        SYSTEM = "system"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    kind = models.CharField(max_length=20, choices=Kind.choices)
    severity = models.CharField(max_length=8, choices=Severity.choices, default=Severity.INFO)
    title = models.CharField(max_length=120)
    message = models.CharField(max_length=500)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=["user", "is_read", "-created_at"], name="notif_user_read_time_idx")]
