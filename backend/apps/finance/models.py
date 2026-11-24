"""Categories, transactions and budgets. Amounts, descriptions and notes are encrypted at rest."""
import uuid

from django.conf import settings
from django.db import models

from apps.core.models import EncryptedRecordMixin, OwnedQuerySet
from apps.core.money import validate_amount

SYSTEM_CATEGORIES = [
    ("Food", "utensils", "#f97316"),
    ("Transportation", "car", "#0ea5e9"),
    ("Shopping", "shopping-bag", "#a855f7"),
    ("Education", "graduation-cap", "#6366f1"),
    ("Healthcare", "heart-pulse", "#ef4444"),
    ("Entertainment", "clapperboard", "#ec4899"),
    ("Bills", "receipt", "#eab308"),
    ("Housing", "house", "#14b8a6"),
    ("Other", "ellipsis", "#64748b"),
]


class Category(models.Model):
    """user = NULL marks a system category shared by everyone (read-only for users)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE, related_name="categories")
    name = models.CharField(max_length=50)
    icon = models.CharField(max_length=30, blank=True)
    color = models.CharField(max_length=7, blank=True)

    class Meta:
        verbose_name_plural = "categories"
        constraints = [
            models.UniqueConstraint(fields=["user", "name"], condition=models.Q(user__isnull=False), name="uniq_user_category_name"),
            models.UniqueConstraint(fields=["name"], condition=models.Q(user__isnull=True), name="uniq_system_category_name"),
        ]

    @property
    def is_system(self):
        return self.user_id is None

    def __str__(self):
        return self.name


class TransactionType(models.TextChoices):
    INCOME = "income", "Income"
    EXPENSE = "expense", "Expense"


class Transaction(EncryptedRecordMixin, models.Model):
    """
    Plaintext (indexable): user, category, type, date.
    Encrypted (AES-256-GCM): amount, description, notes.
    Aggregation and text search therefore run in the application, per user, after decryption.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="transactions")
    category = models.ForeignKey(Category, on_delete=models.PROTECT, related_name="transactions")
    type = models.CharField(max_length=7, choices=TransactionType.choices)
    occurred_on = models.DateField()
    amount_enc = models.TextField()
    description_enc = models.TextField(blank=True, default="")
    notes_enc = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OwnedQuerySet.as_manager()

    class Meta:
        constraints = [models.CheckConstraint(condition=models.Q(type__in=["income", "expense"]), name="tx_type_valid")]
        indexes = [
            models.Index(fields=["user", "-occurred_on"], name="tx_user_date_idx"),
            models.Index(fields=["user", "category", "occurred_on"], name="tx_user_cat_date_idx"),
            models.Index(fields=["user", "type", "occurred_on"], name="tx_user_type_date_idx"),
        ]

    @property
    def amount(self):
        from decimal import Decimal

        return Decimal(self._get_encrypted("amount"))

    @amount.setter
    def amount(self, value):
        self._set_encrypted("amount", str(validate_amount(value)))

    @property
    def description(self):
        return self._get_encrypted("description")

    @description.setter
    def description(self, value):
        self._set_encrypted("description", value)

    @property
    def notes(self):
        return self._get_encrypted("notes")

    @notes.setter
    def notes(self, value):
        self._set_encrypted("notes", value)


class Budget(EncryptedRecordMixin, models.Model):
    """category = NULL is the overall monthly budget. `month` is always the first day of the month."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="budgets")
    category = models.ForeignKey(Category, null=True, blank=True, on_delete=models.CASCADE, related_name="budgets")
    month = models.DateField()
    limit_enc = models.TextField()
    warn_percent = models.PositiveSmallIntegerField(default=80)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OwnedQuerySet.as_manager()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "category", "month"], condition=models.Q(category__isnull=False), name="uniq_budget_user_cat_month"),
            models.UniqueConstraint(fields=["user", "month"], condition=models.Q(category__isnull=True), name="uniq_budget_user_overall_month"),
            models.CheckConstraint(condition=models.Q(warn_percent__gte=1, warn_percent__lte=100), name="budget_warn_percent_range"),
        ]
        indexes = [models.Index(fields=["user", "month"], name="budget_user_month_idx")]

    def save(self, *args, **kwargs):
        self.month = self.month.replace(day=1)
        super().save(*args, **kwargs)

    @property
    def limit(self):
        from decimal import Decimal

        return Decimal(self._get_encrypted("limit"))

    @limit.setter
    def limit(self, value):
        self._set_encrypted("limit", str(validate_amount(value)))
