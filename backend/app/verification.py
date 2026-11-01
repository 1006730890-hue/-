"""Persistent MFA challenges bound to pending actions."""
import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .db import db


MAX_ATTEMPTS = 3
PBKDF2_ITERATIONS = 120_000


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    code: str
    attempts_remaining: int
    accepted_counter: int | None = None


def _digest(code, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", code.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )


def issue(action_id: int, ttl_seconds: int = 120) -> str:
    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_bytes(16)
    digest = _digest(code, salt)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    with db() as conn:
        cur = conn.execute(
            """UPDATE pending_actions
               SET mfa_hash=?, mfa_salt=?, mfa_expires_at=?, mfa_attempts=0
               WHERE id=? AND status='pending' AND mfa_required=1""",
            (
                base64.b64encode(digest).decode("ascii"),
                base64.b64encode(salt).decode("ascii"),
                expires_at.isoformat(),
                action_id,
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("MFA action is missing or unavailable")
    return code


def verify(action_id: int, code: str) -> VerificationResult:
    with db() as conn:
        row = conn.execute(
            """SELECT mfa_hash,mfa_salt,mfa_expires_at,mfa_attempts
               FROM pending_actions WHERE id=?""",
            (action_id,),
        ).fetchone()
        if not row or not row["mfa_hash"] or not row["mfa_salt"]:
            return VerificationResult(False, "challenge_missing", 0)

        attempts = int(row["mfa_attempts"] or 0)
        if attempts >= MAX_ATTEMPTS:
            return VerificationResult(False, "attempts_exhausted", 0)

        expires_at = datetime.fromisoformat(row["mfa_expires_at"])
        if expires_at <= datetime.now(timezone.utc):
            return VerificationResult(
                False, "challenge_expired", MAX_ATTEMPTS - attempts
            )

        salt = base64.b64decode(row["mfa_salt"])
        expected = base64.b64decode(row["mfa_hash"])
        candidate = _digest(code or "", salt)
        if not hmac.compare_digest(candidate, expected):
            attempts += 1
            conn.execute(
                "UPDATE pending_actions SET mfa_attempts=? WHERE id=?",
                (attempts, action_id),
            )
            result_code = (
                "attempts_exhausted" if attempts >= MAX_ATTEMPTS else "invalid_code"
            )
            return VerificationResult(
                False, result_code, max(0, MAX_ATTEMPTS - attempts)
            )

        conn.execute(
            """UPDATE pending_actions
               SET mfa_hash=NULL,mfa_salt=NULL,mfa_expires_at=NULL,mfa_attempts=0
               WHERE id=?""",
            (action_id,),
        )
        return VerificationResult(True, "verified", MAX_ATTEMPTS)


def _totp(secret,counter):
    import struct
    digest = hmac.new(base64.b32decode(secret.upper()+'='*(-len(secret)%8)),struct.pack('>Q',counter),hashlib.sha1).digest()
    offset = digest[-1]&15
    value = (int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%1_000_000
    return f'{value:06d}'


def verify_totp(action_id,user_id,code):
    import json
    import time
    from . import config
    from .db import transaction
    secret = json.loads(config.settings.MFA_TOTP_SECRETS).get(str(user_id))
    if not secret or not isinstance(code,str) or not code.isdigit() or len(code)!=6:
        return VerificationResult(False,'totp_invalid',MAX_ATTEMPTS)
    with transaction() as conn:
        row = conn.execute('SELECT mfa_attempts FROM pending_actions WHERE id=? AND user_id=? AND status=\'pending\'',(action_id,user_id)).fetchone()
        if not row or row['mfa_attempts']>=MAX_ATTEMPTS:
            return VerificationResult(False,'attempts_exhausted',0)
        previous = conn.execute('SELECT counter FROM mfa_totp_counters WHERE user_id=?',(user_id,)).fetchone()
        current = int(time.time())//30
        accepted = next((n for n in (current,current-1,current+1) if (not previous or n>previous['counter']) and hmac.compare_digest(_totp(secret,n),code)),None)
        if accepted is None:
            attempts = row['mfa_attempts']+1
            conn.execute('UPDATE pending_actions SET mfa_attempts=? WHERE id=?',(attempts,action_id))
            return VerificationResult(False,'totp_invalid',max(0,MAX_ATTEMPTS-attempts))
        conn.execute('INSERT INTO mfa_totp_counters(user_id,counter) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET counter=excluded.counter',(user_id,accepted))
        return VerificationResult(True,'verified',MAX_ATTEMPTS,accepted)
