"""
Write-side API for the audit trail, security events and notifications.

Tamper evidence: every AuditLog row stores prev_hash (the previous row's
entry_hash) and entry_hash = HMAC-SHA256(AUDIT_HMAC_KEY, prev_hash | canonical row).
Editing or deleting a row in the middle breaks the chain, and `verify_chain()`
reports the first broken id. Without the HMAC key, an attacker who can write to
the database cannot recompute valid hashes. (Truncating the *tail* is only
detectable by comparing against an externally stored anchor.)
"""
import hashlib
import hmac
import json
from dataclasses import dataclass

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.core.utils import get_client_ip, get_user_agent

from .models import AuditLog, Notification, SecurityEvent, Severity

GENESIS_HASH = "0" * 64
# Audit details may identify *what* changed, never the sensitive values themselves.
FORBIDDEN_DETAIL_KEYS = {"amount", "description", "notes", "limit", "password", "token", "secret", "code", "otp"}


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _entry_hash(prev_hash: str, payload: dict) -> str:
    msg = prev_hash.encode("ascii") + b"|" + _canonical(payload)
    return hmac.new(settings.AUDIT_HMAC_KEY, msg, hashlib.sha256).hexdigest()


def _payload_of(log: AuditLog) -> dict:
    return {
        "created_at": log.created_at.isoformat(),
        "actor_id": str(log.actor_id) if log.actor_id else "",
        "actor_email": log.actor_email,
        "action": log.action,
        "target_type": log.target_type,
        "target_id": log.target_id,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "details": log.details,
    }


def _request_meta(request, ip_address, user_agent):
    if request is not None:
        ip_address = ip_address or get_client_ip(request)
        user_agent = user_agent or get_user_agent(request)
    return (ip_address or ""), (user_agent or "")[:400]


def record_audit(*, action, actor=None, request=None, target_type="", target_id="", details=None, ip_address=None, user_agent=None):
    details = json.loads(json.dumps(details or {}, default=str))  # normalise so stored == hashed
    leaked = FORBIDDEN_DETAIL_KEYS & {str(k).lower() for k in details}
    if leaked:
        raise ValueError(f"Audit details must not contain sensitive keys: {sorted(leaked)}")
    ip_address, user_agent = _request_meta(request, ip_address, user_agent)

    with transaction.atomic():
        last = AuditLog.objects.select_for_update().order_by("-id").first()  # serialises concurrent writers
        log = AuditLog(
            actor_id=actor.pk if actor is not None else None,
            actor_email=actor.email if actor is not None else "",
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else "",
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            created_at=timezone.now(),
            prev_hash=last.entry_hash if last else GENESIS_HASH,
        )
        log.entry_hash = _entry_hash(log.prev_hash, _payload_of(log))
        log.save()
    return log


@dataclass
class ChainResult:
    ok: bool
    checked: int
    first_bad_id: int | None = None
    reason: str = ""


def verify_chain() -> ChainResult:
    prev, checked = GENESIS_HASH, 0
    for log in AuditLog.objects.order_by("id").iterator():
        if log.prev_hash != prev:
            return ChainResult(False, checked, log.id, "broken link (row deleted or reordered)")
        if not hmac.compare_digest(log.entry_hash, _entry_hash(log.prev_hash, _payload_of(log))):
            return ChainResult(False, checked, log.id, "entry hash mismatch (row modified)")
        prev, checked = log.entry_hash, checked + 1
    return ChainResult(True, checked)


def record_security_event(*, event_type, severity=Severity.INFO, user=None, request=None, ip_address=None, user_agent=None, metadata=None):
    ip_address, user_agent = _request_meta(request, ip_address, user_agent)
    return SecurityEvent.objects.create(
        user=user, event_type=event_type, severity=severity, ip_address=ip_address, user_agent=user_agent, metadata=metadata or {}
    )


def notify_user(user, *, kind, title, message, severity=Severity.INFO):
    """Messages must never contain financial amounts or secrets."""
    return Notification.objects.create(user=user, kind=kind, title=title[:120], message=message[:500], severity=severity)
