"""Server-owned banking policy, persisted lockout and JianHeng input screen."""
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from .db import db, transaction
from . import config
from .money import transfer_amount
from .duplex.detection import inspect_local

GREEN, YELLOW, RED = 'green', 'yellow', 'red'
TOOL_RISK = {
    'get_balance': GREEN, 'list_transactions': GREEN, 'monthly_bill': GREEN,
    'detect_anomaly': GREEN, 'list_cards': GREEN, 'list_subscriptions': GREEN,
    'list_wealth_products': GREEN, 'compare_products': GREEN, 'get_holdings': GREEN,
    'list_goals': GREEN, 'cancel_subscription': YELLOW, 'toggle_card_freeze': YELLOW,
    'spending_report': GREEN, 'recommend_wealth': GREEN, 'find_recipients': GREEN,
    'schedule_transfer': YELLOW, 'create_aa_request': YELLOW,
    'create_goal': YELLOW, 'transfer': RED, 'purchase_wealth': RED, 'redeem_wealth': RED,
    'report_card_loss': RED, 'adjust_credit_limit': RED,
}

@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk: str
    code: str = 'allowed'
    reason: str = ''

@dataclass(frozen=True)
class LockState:
    locked: bool
    attempts: int
    reason: str = ''


def get_lock_state(user_id):
    with db() as conn:
        row = conn.execute('SELECT * FROM security_states WHERE user_id=?', (user_id,)).fetchone()
    if not row:
        return LockState(False, 0)
    locked = bool(row['locked_until'] and datetime.fromisoformat(row['locked_until']) > datetime.now(timezone.utc))
    attempts = row['attempts'] if not row['locked_until'] or locked else 0
    return LockState(locked, attempts, row['reason'] or '')


def note_fail(user_id, reason='operation_failed'):
    with transaction() as conn:
        state = get_lock_state(user_id)
        attempts = state.attempts + 1
        locked = attempts >= config.settings.MAX_CONSECUTIVE_FAIL
        until = (datetime.now(timezone.utc) + timedelta(seconds=config.settings.LOCK_SECONDS)).isoformat() if locked else None
        conn.execute('''INSERT INTO security_states(user_id,attempts,reason,locked_until,updated_at)
                        VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                        attempts=excluded.attempts,reason=excluded.reason,locked_until=excluded.locked_until,updated_at=excluded.updated_at''',
                     (user_id, attempts, reason, until, datetime.now(timezone.utc).isoformat()))
    return locked


def note_success(user_id, category='green_query'):
    if category == 'mfa':
        with db() as conn:
            conn.execute('UPDATE security_states SET attempts=0,locked_until=NULL,reason=NULL WHERE user_id=?', (user_id,))


def is_locked(user_id):
    return get_lock_state(user_id).locked


def today_transfer_total(user_id):
    with db() as conn:
        row = conn.execute("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE user_id=? AND txn_type='transfer_out' AND ts LIKE ?",
                           (user_id, date.today().isoformat()+'%')).fetchone()
    return round(row['s'], 2)


def classify(name, args, user_id):
    if name == 'transfer':
        amount = transfer_amount(args.get('amount'))
        return YELLOW if today_transfer_total(user_id) + amount <= config.settings.DAILY_YELLOW_LIMIT else RED
    return TOOL_RISK.get(name, RED)


def decide(name, args, user_id):
    if name not in TOOL_RISK:
        return PolicyDecision(False, RED, 'unknown_tool', '工具未注册')
    if not isinstance(args, dict):
        return PolicyDecision(False, RED, 'invalid_arguments', '参数必须是对象')
    if name in ('transfer', 'purchase_wealth', 'redeem_wealth', 'adjust_credit_limit'):
        try:
            amount = transfer_amount(args.get('new_limit') if name == 'adjust_credit_limit' else args.get('amount'))
        except ValueError as exc:
            return PolicyDecision(False, RED, 'invalid_amount', str(exc))
        if name == 'transfer' and today_transfer_total(user_id) + amount > config.settings.DAILY_TRANSFER_LIMIT:
            return PolicyDecision(False, RED, 'daily_transfer_limit_exceeded', '超出单日转账上限')
    if is_locked(user_id) and TOOL_RISK[name] != GREEN:
        return PolicyDecision(False, RED, 'account_locked', '账户操作临时锁定')
    return PolicyDecision(True, classify(name, args, user_id))


def mfa_required(risk):
    return risk == RED


def detect_prompt_injection(text):
    return inspect_local(text)
