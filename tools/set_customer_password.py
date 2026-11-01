"""Local operator password reset. Prompts interactively; never prints the chosen password."""
import argparse
import base64
import getpass
from pathlib import Path
import secrets
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from app import customer_auth,audit
from app.db import init_db,transaction


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name',required=True)
    args = parser.parse_args()
    password = getpass.getpass('New customer password (at least 12 characters): ')
    if len(password)<12 or getpass.getpass('Repeat new password: ') != password:
        raise SystemExit('Password length or confirmation is invalid')
    init_db()
    with transaction() as conn:
        rows = conn.execute('SELECT id FROM users WHERE name=?',(args.name,)).fetchall()
        if len(rows)!=1:
            raise SystemExit('Customer name is missing or ambiguous')
        uid = rows[0]['id']
        salt = secrets.token_bytes(16)
        conn.execute('''INSERT INTO customer_credentials(user_id,password_hash,salt) VALUES(?,?,?)
                        ON CONFLICT(user_id) DO UPDATE SET password_hash=excluded.password_hash,salt=excluded.salt''',
                     (uid,customer_auth._digest(password,salt),base64.b64encode(salt).decode()))
        conn.execute('DELETE FROM customer_sessions WHERE user_id=?',(uid,))
        conn.execute('DELETE FROM customer_login_limits WHERE login_name=?',(args.name,))
        audit.log(uid,'local_operator','password_reset',{}, {'sessions_revoked':True},'red')
    print('Password changed; previous customer sessions have been revoked.')


if __name__ == '__main__':
    main()
