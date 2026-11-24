from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError

MAX_AMOUNT = Decimal("999999999.99")
_CENT = Decimal("0.01")


def validate_amount(value) -> Decimal:
    """Return a positive, 2-decimal Decimal or raise ValidationError. Floats are rejected."""
    if isinstance(value, (float, bool)):
        raise ValidationError("Money must be a Decimal or string, never a float.")
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        raise ValidationError("Invalid amount.") from None
    if not amount.is_finite():
        raise ValidationError("Invalid amount.")
    if amount <= 0:
        raise ValidationError("Amount must be greater than zero.")
    if amount != amount.quantize(_CENT):
        raise ValidationError("Amount may have at most 2 decimal places.")
    if amount > MAX_AMOUNT:
        raise ValidationError("Amount is too large.")
    return amount.quantize(_CENT)
