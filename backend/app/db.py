"""SQLite 连接与建表（stdlib，零重依赖）。"""
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from contextvars import ContextVar
from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY, name TEXT, phone TEXT, token TEXT,
    risk_level TEXT DEFAULT '稳健型'
);
CREATE TABLE IF NOT EXISTS accounts(
    id INTEGER PRIMARY KEY, user_id INTEGER, account_no TEXT, balance REAL
);
CREATE TABLE IF NOT EXISTS cards(
    id INTEGER PRIMARY KEY, user_id INTEGER, card_no TEXT, holder TEXT,
    card_type TEXT, status TEXT DEFAULT 'normal', credit_limit REAL DEFAULT 0,
    remaining_limit REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS transactions(
    id INTEGER PRIMARY KEY, user_id INTEGER, ts TEXT, counterparty TEXT,
    category TEXT, amount REAL, txn_type TEXT, merchant TEXT
);
CREATE TABLE IF NOT EXISTS subscriptions(
    id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, amount REAL,
    cycle TEXT, next_charge TEXT, status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS wealth_products(
    id INTEGER PRIMARY KEY, name TEXT, risk_level TEXT, annual_return REAL,
    min_amount REAL, ptype TEXT
);
CREATE TABLE IF NOT EXISTS holdings(
    id INTEGER PRIMARY KEY, user_id INTEGER, product_name TEXT, amount REAL
);
CREATE TABLE IF NOT EXISTS audit_logs(
    id INTEGER PRIMARY KEY, ts TEXT, user_id INTEGER, actor TEXT,
    action TEXT, params TEXT, result TEXT, risk_level TEXT, decision_chain TEXT
);
CREATE TABLE IF NOT EXISTS pending_actions(
    id INTEGER PRIMARY KEY, user_id INTEGER, tool_name TEXT, args TEXT,
    risk_level TEXT, status TEXT DEFAULT 'pending', created_at TEXT,
    mfa_required INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS goals(
    id INTEGER PRIMARY KEY, user_id INTEGER, description TEXT,
    due_date TEXT, plan TEXT, status TEXT DEFAULT 'active'
);
"""


_active_connection = ContextVar("bank_transaction", default=None)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db():
    existing = _active_connection.get()
    if existing is not None:
        yield existing
        return
    conn = get_conn()
    token = _active_connection.set(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _active_connection.reset(token)
        conn.close()


@contextmanager
def transaction():
    """Serialize confirmation, ledger writes and audit on the same connection."""
    with db() as conn:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        yield conn


def init_db():
    Path(settings.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
        conn.executescript('''
          CREATE TABLE IF NOT EXISTS conversations(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,created_at TEXT,updated_at TEXT,active_request TEXT);
          CREATE TABLE IF NOT EXISTS recipients(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,name TEXT NOT NULL,phone TEXT,account_no TEXT NOT NULL,label TEXT);
          CREATE TABLE IF NOT EXISTS security_states(user_id INTEGER PRIMARY KEY,attempts INTEGER DEFAULT 0,reason TEXT,locked_until TEXT,updated_at TEXT);
        ''')
        conn.executescript(Path(__file__).with_name("admin_schema.sql").read_text(encoding="utf-8"))
        additions = {
            "pending_actions": {
                "action_token": "TEXT", "payload_hash": "TEXT", "expires_at": "TEXT",
                "mfa_hash": "TEXT", "mfa_salt": "TEXT", "mfa_expires_at": "TEXT",
                "mfa_attempts": "INTEGER DEFAULT 0", "executed_at": "TEXT", "task_id": "TEXT",
                "conversation_id": "TEXT", "root_instruction": "TEXT", "secure_plan": "TEXT",
                "policy_version": "TEXT", "origin_request": "TEXT", "mfa_verified": "INTEGER DEFAULT 0", "mfa_method": "TEXT DEFAULT 'local_outbox'",
            },
            "audit_logs": {"prev_hash": "TEXT", "entry_hash": "TEXT", "duplex_hash": "TEXT"},
            "recipients": {"label": "TEXT"},
            "conversations": {"active_request": "TEXT", "clarification_state": "TEXT"},
            "security_states": {"attempts": "INTEGER DEFAULT 0", "reason": "TEXT"},
        }
        for table, columns in additions.items():
            present = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            for name, declaration in columns.items():
                if name not in present:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS security_states(
          user_id INTEGER PRIMARY KEY, attempts INTEGER DEFAULT 0, reason TEXT,
          locked_until TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS conversations(
          id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS conversation_messages(
          id INTEGER PRIMARY KEY, conversation_id TEXT, role TEXT, content TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS agent_tasks(
          id TEXT PRIMARY KEY, conversation_id TEXT, user_id INTEGER, title TEXT,
          status TEXT DEFAULT 'running', review_reason TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS task_nodes(
          id TEXT PRIMARY KEY, task_id TEXT, node_key TEXT, tool_name TEXT, status TEXT,
          dependencies TEXT, risk_level TEXT, result TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS recipients(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
          phone TEXT, account_no TEXT NOT NULL, label TEXT);
        CREATE TABLE IF NOT EXISTS scheduled_transfers(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL,
          amount REAL NOT NULL, execute_at TEXT NOT NULL, note TEXT, status TEXT DEFAULT 'scheduled',
          created_at TEXT);
        CREATE TABLE IF NOT EXISTS aa_requests(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL,
          total_amount REAL NOT NULL, participant_count INTEGER NOT NULL, per_person REAL NOT NULL,
          status TEXT DEFAULT 'open', created_at TEXT);
        CREATE TABLE IF NOT EXISTS customer_credentials(user_id INTEGER PRIMARY KEY,password_hash TEXT NOT NULL,salt TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS customer_sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS customer_login_limits(login_name TEXT PRIMARY KEY,attempts INTEGER DEFAULT 0,locked_until TEXT);
        CREATE TABLE IF NOT EXISTS mfa_totp_counters(user_id INTEGER PRIMARY KEY,counter INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS duplex_memories(
          id INTEGER PRIMARY KEY, user_id INTEGER, conversation_id TEXT, content TEXT,
          trust TEXT DEFAULT 'untrusted', created_at TEXT);
        CREATE TABLE IF NOT EXISTS duplex_runs(
          id TEXT PRIMARY KEY, user_id INTEGER, conversation_id TEXT, root_instruction TEXT,
          mode TEXT, plan TEXT, evidence TEXT, created_at TEXT);
        """)
