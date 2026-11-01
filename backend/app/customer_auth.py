"""Customer credentials and revocable sessions; fixed sample tokens work only in explicit demo mode."""
import base64
from contextvars import ContextVar
from datetime import datetime,timedelta,timezone
import hashlib
import hmac
from pathlib import Path
import secrets
from . import config,audit
from .db import db,transaction

request_token = ContextVar('customer_bearer_token',default='')


def _digest(password,salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000).hex()


def initialize():
    notices = []
    with transaction() as conn:
        rows = conn.execute('SELECT id,name FROM users WHERE id NOT IN (SELECT user_id FROM customer_credentials)').fetchall()
        for row in rows:
            password,salt = secrets.token_urlsafe(15),secrets.token_bytes(16)
            conn.execute('INSERT INTO customer_credentials(user_id,password_hash,salt) VALUES(?,?,?)',
                         (row['id'],_digest(password,salt),base64.b64encode(salt).decode()))
            notices.append(f"登录名：{row['name']}\n初始密码：{password}\n")
    if notices:
        target = Path(config.settings.DB_PATH).parent/'initial-customer-access.txt'
        target.write_text('本机首次启动的客户凭据。请妥善保管，不要提交到代码仓库。\n\n'+'\n'.join(notices),encoding='utf-8')


def resolve(token):
    token = request_token.get() or token
    with db() as conn:
        hashed = hashlib.sha256((token or '').encode()).hexdigest()
        session = conn.execute('SELECT user_id,expires_at FROM customer_sessions WHERE token_hash=?',(hashed,)).fetchone()
        if session and datetime.fromisoformat(session['expires_at']) > datetime.now(timezone.utc):
            return session['user_id']
        if config.settings.DEMO_MODE:
            row = conn.execute('SELECT id FROM users WHERE token=?',(token,)).fetchone()
            return row['id'] if row else None
    return None


def login(login_name,password):
    current = datetime.now(timezone.utc)
    with transaction() as conn:
        limit = conn.execute('SELECT * FROM customer_login_limits WHERE login_name=?',(login_name,)).fetchone()
        if limit and limit['locked_until'] and datetime.fromisoformat(limit['locked_until'])>current:
            return {'ok':False,'code':'login_locked','reply':'登录尝试过多，请5分钟后重试。'}
        rows = conn.execute('''SELECT u.id,c.password_hash,c.salt FROM users u
                              JOIN customer_credentials c ON c.user_id=u.id WHERE u.name=?''',(login_name,)).fetchall()
        row = rows[0] if len(rows)==1 else None
        salt = base64.b64decode(row['salt']) if row else bytes(16)
        candidate = _digest(password,salt)
        if not row or not hmac.compare_digest(candidate,row['password_hash']):
            attempts = (limit['attempts'] if limit and not limit['locked_until'] else 0)+1
            until = (current+timedelta(minutes=5)).isoformat() if attempts>=5 else None
            conn.execute('''INSERT INTO customer_login_limits(login_name,attempts,locked_until) VALUES(?,?,?)
                            ON CONFLICT(login_name) DO UPDATE SET attempts=excluded.attempts,locked_until=excluded.locked_until''',(login_name,attempts,until))
            return {'ok':False,'code':'invalid_credentials','reply':'登录名或密码不正确。'}
        conn.execute('DELETE FROM customer_login_limits WHERE login_name=?',(login_name,))
        token = secrets.token_urlsafe(32)
        expires = (current+timedelta(hours=8)).isoformat()
        conn.execute('INSERT INTO customer_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',
                     (hashlib.sha256(token.encode()).hexdigest(),row['id'],expires))
        audit.log(row['id'],'customer','login',{}, {'ok':True},'green')
    return {'ok':True,'token':token,'expires_at':expires,'name':login_name}


def logout(token):
    token = request_token.get() or token
    with db() as conn:
        conn.execute('DELETE FROM customer_sessions WHERE token_hash=?',(hashlib.sha256((token or '').encode()).hexdigest(),))
