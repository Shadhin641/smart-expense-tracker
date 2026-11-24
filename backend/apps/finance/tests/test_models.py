from datetime import date
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.test import TestCase

from apps.accounts.models import User
from apps.core.crypto import DecryptionError
from apps.finance.models import Budget, Category, Transaction


def make_tx(user, category, **kw):
    defaults = dict(type="expense", occurred_on=date(2026, 11, 3), amount=Decimal("1234.56"), description="Rent for flat", notes="paid cash")
    defaults.update(kw)
    return Transaction.objects.create(user=user, category=category, **defaults)


class FinanceBase(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice@example.com", "pw-pw-pw-pw-pw")
        self.bob = User.objects.create_user("bob@example.com", "pw-pw-pw-pw-pw")
        self.food = Category.objects.get(user=None, name="Food")


class CategoryTests(FinanceBase):
    def test_nine_system_categories_seeded(self):
        names = set(Category.objects.filter(user=None).values_list("name", flat=True))
        self.assertEqual(names, {"Food", "Transportation", "Shopping", "Education", "Healthcare", "Entertainment", "Bills", "Housing", "Other"})

    def test_unique_names(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Category.objects.create(user=None, name="Food")
        Category.objects.create(user=self.alice, name="Pets")
        with self.assertRaises(IntegrityError), transaction.atomic():
            Category.objects.create(user=self.alice, name="Pets")
        Category.objects.create(user=self.bob, name="Pets")  # same name, other user: fine


class TransactionEncryptionTests(FinanceBase):
    def test_sensitive_columns_are_ciphertext_in_the_database(self):
        tx = make_tx(self.alice, self.food)
        with connection.cursor() as cur:
            cur.execute("SELECT amount_enc, description_enc, notes_enc FROM finance_transaction WHERE id = %s", [tx.pk.hex])
            row = cur.fetchone()
        blob = " ".join(row)
        for plaintext in ("1234.56", "Rent", "paid cash"):
            self.assertNotIn(plaintext, blob)
        reloaded = Transaction.objects.get(pk=tx.pk)
        self.assertEqual((reloaded.amount, reloaded.description, reloaded.notes), (Decimal("1234.56"), "Rent for flat", "paid cash"))

    def test_ciphertext_cannot_be_moved_between_rows_users_or_fields(self):
        a1, a2 = make_tx(self.alice, self.food), make_tx(self.alice, self.food, amount=Decimal("5.00"))
        b1 = make_tx(self.bob, self.food, amount=Decimal("9.00"))
        a2.amount_enc = a1.amount_enc  # same user, other row
        with self.assertRaises(DecryptionError):
            a2.amount
        b1.amount_enc = a1.amount_enc  # other user
        with self.assertRaises(DecryptionError):
            b1.amount
        a1.amount_enc = a1.description_enc  # other field
        with self.assertRaises(DecryptionError):
            a1.amount

    def test_amount_validation(self):
        for bad in (Decimal("-1"), Decimal("0"), 12.5, "abc"):
            with self.assertRaises(ValidationError):
                make_tx(self.alice, self.food, amount=bad)

    def test_for_user_isolates_records(self):
        make_tx(self.alice, self.food)
        make_tx(self.bob, self.food)
        self.assertEqual(Transaction.objects.for_user(self.alice).count(), 1)
        self.assertEqual(Transaction.objects.for_user(self.alice).get().user_id, self.alice.pk)

    def test_invalid_type_rejected_by_database(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            make_tx(self.alice, self.food, type="gift")


class BudgetTests(FinanceBase):
    def test_limit_encrypted_and_month_normalised(self):
        budget = Budget.objects.create(user=self.alice, category=self.food, month=date(2026, 11, 17), limit=Decimal("5000"))
        self.assertEqual(budget.month, date(2026, 11, 1))
        with connection.cursor() as cur:
            cur.execute("SELECT limit_enc FROM finance_budget")
            self.assertNotIn("5000", cur.fetchone()[0])
        self.assertEqual(Budget.objects.get(pk=budget.pk).limit, Decimal("5000.00"))

    def test_uniqueness_rules(self):
        Budget.objects.create(user=self.alice, category=self.food, month=date(2026, 11, 1), limit=Decimal("100"))
        Budget.objects.create(user=self.alice, category=None, month=date(2026, 11, 1), limit=Decimal("900"))  # overall
        for cat in (self.food, None):
            with self.assertRaises(IntegrityError), transaction.atomic():
                Budget.objects.create(user=self.alice, category=cat, month=date(2026, 11, 20), limit=Decimal("1"))
        Budget.objects.create(user=self.bob, category=self.food, month=date(2026, 11, 1), limit=Decimal("100"))

    def test_warn_percent_bounds(self):
        for bad in (0, 101):
            with self.assertRaises(IntegrityError), transaction.atomic():
                Budget.objects.create(user=self.alice, category=self.food, month=date(2026, 12, 1), limit=Decimal("1"), warn_percent=bad)
