"""Validate transfer inputs before policy evaluation or ledger changes."""
from decimal import Decimal, InvalidOperation


def transfer_amount(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("转账金额必须是有效数字")
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("转账金额必须是有效数字") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValueError("转账金额必须是大于 0 的有限数字")
    try:
        rounded = amount.quantize(Decimal("0.01"))
    except InvalidOperation as exc:
        raise ValueError("转账金额超出有效范围") from exc
    if amount != rounded:
        raise ValueError("转账金额最多保留两位小数")
    return float(amount)
