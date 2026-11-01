"""Transactional append-only audit hash chain (legacy import is marked explicitly)."""
import hashlib
import json
from datetime import datetime, timezone
from .db import db, transaction

FIELDS = ('id','ts','user_id','actor','action','params','result','risk_level','decision_chain')
GENESIS = '0' * 64


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _hash(row, previous):
    return hashlib.sha256(canonical({'previous': previous, 'entry': {k: row[k] for k in FIELDS}}).encode()).hexdigest()


def _backfill(conn):
    first = conn.execute('SELECT duplex_hash FROM audit_logs ORDER BY id LIMIT 1').fetchone()
    if not first or first['duplex_hash']:
        return
    rows = conn.execute('SELECT * FROM audit_logs ORDER BY id').fetchall()
    if rows and all(not r['duplex_hash'] for r in rows):
        previous = GENESIS
        for row in rows:
            digest = _hash(row, previous)
            conn.execute('UPDATE audit_logs SET prev_hash=?,duplex_hash=? WHERE id=?', (previous, digest, row['id']))
            previous = digest


def log(user_id, actor, action, params, result, risk_level, decision_chain=None):
    with transaction() as conn:
        _backfill(conn)
        previous = conn.execute('SELECT duplex_hash FROM audit_logs ORDER BY id DESC LIMIT 1').fetchone()
        previous = previous['duplex_hash'] if previous else GENESIS
        cur = conn.execute('''INSERT INTO audit_logs(ts,user_id,actor,action,params,result,risk_level,decision_chain,prev_hash)
                              VALUES(?,?,?,?,?,?,?,?,?)''',
                           (datetime.now(timezone.utc).isoformat(),user_id,actor,action,canonical(params),
                            canonical(result),risk_level,canonical(decision_chain or []),previous))
        row = conn.execute('SELECT * FROM audit_logs WHERE id=?', (cur.lastrowid,)).fetchone()
        conn.execute('UPDATE audit_logs SET duplex_hash=? WHERE id=?', (_hash(row, previous), cur.lastrowid))
        return cur.lastrowid


def verify_chain():
    with transaction() as conn:
        _backfill(conn)
        rows = conn.execute('SELECT * FROM audit_logs ORDER BY id').fetchall()
    previous = GENESIS
    for index, row in enumerate(rows):
        if row['prev_hash'] != previous or row['duplex_hash'] != _hash(row, previous):
            return {'valid': False, 'checked': index, 'broken_at': row['id'], 'head_hash': previous}
        previous = row['duplex_hash']
    return {'valid': True, 'checked': len(rows), 'head_hash': previous}


def list_logs(user_id=None, limit=50):
    sql, params = 'SELECT * FROM audit_logs', []
    if user_id is not None:
        sql += ' WHERE user_id=?'
        params.append(user_id)
    sql += ' ORDER BY id DESC LIMIT ?'
    params.append(max(1, min(int(limit), 200)))
    with db() as conn:
        return [dict(r) for r in conn.execute(sql, params)]
