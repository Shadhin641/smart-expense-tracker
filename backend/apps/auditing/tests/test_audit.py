import unittest

from django.db import connection
from django.test import RequestFactory, TestCase

from apps.accounts.models import User
from apps.auditing.models import AuditLog, ImmutableRecordError
from apps.auditing.services import GENESIS_HASH, notify_user, record_audit, record_security_event, verify_chain

ACTION = AuditLog.Action
ON_POSTGRES = connection.vendor == "postgresql"


class AuditChainTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", "pw-pw-pw-pw-pw")

    def _make(self, n=3):
        return [record_audit(action=ACTION.LOGIN_SUCCESS, actor=self.user, details={"i": i}) for i in range(n)]

    def test_chain_links_and_verifies(self):
        first, second, third = self._make()
        self.assertEqual(first.prev_hash, GENESIS_HASH)
        self.assertEqual(second.prev_hash, first.entry_hash)
        self.assertEqual(third.prev_hash, second.entry_hash)
        result = verify_chain()
        self.assertTrue(result.ok)
        self.assertEqual(result.checked, 3)

    def test_empty_chain_is_valid(self):
        self.assertTrue(verify_chain().ok)

    def test_request_metadata_recorded(self):
        request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.5", HTTP_USER_AGENT="pytest-agent")
        log = record_audit(action=ACTION.LOGOUT, actor=self.user, request=request)
        self.assertEqual((log.ip_address, log.user_agent, log.actor_email), ("203.0.113.5", "pytest-agent", "a@example.com"))

    def test_sensitive_values_are_refused(self):
        for key in ("amount", "Description", "notes", "password", "token", "otp"):
            with self.assertRaises(ValueError):
                record_audit(action=ACTION.TRANSACTION_CREATED, actor=self.user, details={key: "x"})

    def test_orm_blocks_modification_and_deletion(self):
        log = self._make(1)[0]
        log.action = ACTION.LOGOUT
        with self.assertRaises(ImmutableRecordError):
            log.save()
        with self.assertRaises(ImmutableRecordError):
            log.delete()
        with self.assertRaises(ImmutableRecordError):
            AuditLog.objects.all().update(action="x")
        with self.assertRaises(ImmutableRecordError):
            AuditLog.objects.all().delete()
        with self.assertRaises(ImmutableRecordError):
            AuditLog.objects.bulk_create([AuditLog()])

    @unittest.skipIf(ON_POSTGRES, "PostgreSQL trigger blocks raw tampering; see test below")
    def test_raw_sql_modification_is_detected(self):
        logs = self._make()
        with connection.cursor() as cur:
            cur.execute("UPDATE auditing_auditlog SET details = %s WHERE id = %s", ['{"i": 999}', logs[1].id])
        result = verify_chain()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_id, logs[1].id)

    @unittest.skipIf(ON_POSTGRES, "PostgreSQL trigger blocks raw tampering; see test below")
    def test_raw_sql_deletion_is_detected(self):
        logs = self._make()
        with connection.cursor() as cur:
            cur.execute("DELETE FROM auditing_auditlog WHERE id = %s", [logs[1].id])
        result = verify_chain()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_id, logs[2].id)

    @unittest.skipUnless(ON_POSTGRES, "requires PostgreSQL")
    def test_database_trigger_blocks_update_and_delete(self):
        from django.db import IntegrityError, transaction

        log = self._make(1)[0]
        for sql in ("UPDATE auditing_auditlog SET action = 'x' WHERE id = %s", "DELETE FROM auditing_auditlog WHERE id = %s"):
            with self.assertRaises(IntegrityError), transaction.atomic(), connection.cursor() as cur:
                cur.execute(sql, [log.id])


class EventsAndNotificationsTests(TestCase):
    def test_security_event_and_notification(self):
        user = User.objects.create_user("n@example.com", "pw-pw-pw-pw-pw")
        request = RequestFactory().get("/", REMOTE_ADDR="198.51.100.4")
        event = record_security_event(event_type="suspicious_login", severity="high", user=user, request=request, metadata={"reason": "new_ip"})
        self.assertEqual((event.ip_address, event.severity), ("198.51.100.4", "high"))
        note = notify_user(user, kind="suspicious_login", title="New sign-in", message="We noticed a sign-in from a new device.")
        self.assertFalse(note.is_read)
