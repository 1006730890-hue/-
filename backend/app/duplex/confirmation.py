"""Sealed confirmation snapshots and one atomic, replay-safe execution boundary."""
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .. import config, security, audit, verification, tools
from ..db import db, transaction
from .kernel import POLICY_VERSION, root_authorizes, tool_specs
from .drift_runtime import SecurePlan, validate_arguments
from .detection import scan_arguments


def now():
    return datetime.now(timezone.utc)


def _key():
    location = Path(config.settings.DB_PATH).with_suffix('.duplex.key')
    location.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(location, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return location.read_bytes()
    else:
        value = secrets.token_bytes(32)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
        return value


def seal(row):
    keys = ('user_id','conversation_id','tool_name','args','risk_level','mfa_required',
            'action_token','expires_at','origin_request','mfa_method','root_instruction','secure_plan','policy_version')
    data = {key: row[key] for key in keys}
    encoded = json.dumps(data,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    return hmac.new(_key(), encoded, hashlib.sha256).hexdigest()


def invalidate(user_id, conversation_id=None, reason='superseded'):
    with transaction() as conn:
        query = "UPDATE pending_actions SET status=?,note=? WHERE user_id=? AND status='pending'"
        params = [reason,reason,user_id]
        if conversation_id:
            query += ' AND conversation_id=?'
            params.append(conversation_id)
        return conn.execute(query,params).rowcount


def save(guard, name, args, risk):
    with transaction() as conn:
        if guard.conversation_id and guard.request_id:
            current = conn.execute('SELECT active_request FROM conversations WHERE id=? AND user_id=?',(guard.conversation_id,guard.user_id)).fetchone()
            if not current or current['active_request'] != guard.request_id:
                raise tools.ToolError('请求已被后续消息替代')
        invalidate(guard.user_id,guard.conversation_id)
        timestamp = now()
        snapshot = dict(user_id=guard.user_id,conversation_id=guard.conversation_id,tool_name=name,origin_request=guard.request_id,
            args=json.dumps(args,ensure_ascii=False,sort_keys=True,allow_nan=False),risk_level=risk,
            mfa_required=int(risk == security.RED),mfa_method='demo' if config.settings.DEMO_MODE else config.settings.MFA_PROVIDER,action_token=secrets.token_urlsafe(24),
            expires_at=(timestamp+timedelta(seconds=config.settings.CONFIRM_TTL_SECONDS)).isoformat(),
            root_instruction=guard.root,secure_plan=json.dumps(guard.plan.to_dict(),ensure_ascii=False),
            policy_version=POLICY_VERSION)
        snapshot['payload_hash'] = seal(snapshot)
        keys = list(snapshot)
        query = 'INSERT INTO pending_actions('+','.join(keys)+",status,created_at) VALUES("+','.join('?' for _ in keys)+",'pending',?)"
        cur = conn.execute(query,[snapshot[k] for k in keys]+[timestamp.isoformat()])
        action_id = cur.lastrowid
        code = verification.issue(action_id) if risk == security.RED and snapshot['mfa_method'] != 'totp' else None
        audit.log(guard.user_id,'duplex','pending_confirm',{'tool':name,'args':args},
                  {'action_id':action_id,'run_id':guard.run_id,'expires_at':snapshot['expires_at']},risk)
    # Local delivery is visible only on this machine; demo codes are never sent in normal mode.
    if code and not config.settings.DEMO_MODE:
        outbox = Path(config.settings.DB_PATH).parent / 'local-mfa'
        outbox.mkdir(exist_ok=True)
        (outbox / f'{action_id}.txt').write_text(f'Action {action_id}: {code}\nExpires in 120 seconds.\n',encoding='utf-8')
    return {'reply':'请核对以下业务参数后确认：','needs_confirm':True,
            'confirm':{'action_id':action_id,'tool':name,'args':args,'risk_level':risk,
                       'mfa_method':snapshot['mfa_method'],'mfa_required':risk == security.RED,'demo_mfa_code':code if config.settings.DEMO_MODE else None,
                       'expires_at':snapshot['expires_at'],'currency':'CNY'}}


def fail(code, reply, **extra):
    return {'reply':reply,'executed':False,'code':code,**extra}


def confirm(user_id, action_id, approved, mfa_code=None, conversation_id=None):
    # Perform component requests before acquiring the SQLite writer lock.
    with db() as conn:
        snapshot = conn.execute('SELECT * FROM pending_actions WHERE id=? AND user_id=?',(action_id,user_id)).fetchone()
    if not snapshot:
        return fail('confirmation_missing','未找到该确认请求。')
    if conversation_id and snapshot['conversation_id'] != conversation_id:
        return fail('conversation_mismatch','确认请求不属于当前会话。')
    if snapshot['status'] != 'pending':
        return fail('already_processed','该操作已处理或已被新的请求撤销。')
    try:
        if snapshot['expires_at'] and datetime.fromisoformat(snapshot['expires_at']) <= now():
            return fail('confirmation_expired','确认已过期，请重新发起业务。')
    except (TypeError,ValueError):
        return fail('confirmation_tampered','确认有效期数据无效。',blocked=True)
    if not snapshot['payload_hash'] or not hmac.compare_digest(seal(snapshot),snapshot['payload_hash']):
        return fail('confirmation_tampered','确认请求校验失败，请重新发起业务。',blocked=True)
    args = json.loads(snapshot['args'])
    name = snapshot['tool_name']
    if not approved:
        with transaction() as conn:
            changed = conn.execute("UPDATE pending_actions SET status='rejected' WHERE id=? AND user_id=? AND status='pending'",(action_id,user_id)).rowcount
            if not changed:
                return fail('already_processed','该操作已处理过。')
            audit.log(user_id,'user','reject_action',{'action_id':action_id},{'ok':True},snapshot['risk_level'])
        return fail('rejected','好的，已取消该操作。',rejected=True)
    spec = next((s for s in tool_specs() if s.name == name),None)
    if spec is None or snapshot['policy_version'] != POLICY_VERSION:
        return fail('policy_changed','安全策略已更新，请重新发起业务。')
    plan = SecurePlan.from_dict(json.loads(snapshot['secure_plan']))
    if plan.root_instruction != snapshot['root_instruction']:
        return fail('confirmation_tampered','授权请求与计划不一致。',blocked=True)
    allowed, reason = root_authorizes(snapshot['root_instruction'],name,args)
    if not allowed or validate_arguments(spec,args):
        return fail('authorization_required',reason or '参数验证失败。',blocked=True)
    scan = scan_arguments(name,args,spec.description)
    if scan['decision'] != 'allow':
        return fail(scan.get('code','unsafe_arguments'),scan.get('reason','参数检查拒绝。'),blocked=True)
    authenticated_counter = None
    try:
        with transaction() as conn:
            row = conn.execute('SELECT * FROM pending_actions WHERE id=? AND user_id=?',(action_id,user_id)).fetchone()
            if row['origin_request'] and row['conversation_id']:
                current = conn.execute('SELECT active_request FROM conversations WHERE id=? AND user_id=?',(row['conversation_id'],user_id)).fetchone()
                if not current or current['active_request'] != row['origin_request']:
                    return fail('request_superseded','请求已被后续消息替代。')
            if row['task_id']:
                task = conn.execute('SELECT status FROM agent_tasks WHERE id=? AND user_id=?',(row['task_id'],user_id)).fetchone()
                if not task or task['status'] not in ('waiting_confirmation','waiting_mfa'):
                    return fail('task_state_changed','任务已暂停、取消或转人工，请重新发起业务。')
            if row['status'] != 'pending':
                return fail('already_processed','该操作已处理过。')
            if not hmac.compare_digest(seal(row),row['payload_hash']):
                return fail('confirmation_tampered','确认参数发生变化。',blocked=True)
            if datetime.fromisoformat(row['expires_at']) <= now():
                conn.execute("UPDATE pending_actions SET status='expired' WHERE id=?",(action_id,))
                return fail('confirmation_expired','确认已过期，请重新发起业务。')
            decision = security.decide(name,args,user_id)
            if not decision.allowed:
                return fail(decision.code,decision.reason,blocked=True)
            if decision.risk == security.RED and row['risk_level'] != security.RED:
                conn.execute("UPDATE pending_actions SET status='superseded' WHERE id=?",(action_id,))
                return fail('risk_level_changed','累计额度已变化，请重新提交并完成强验证。')
            if row['risk_level'] == security.RED:
                verified = verification.verify_totp(action_id,user_id,mfa_code or '') if row['mfa_method'] == 'totp' else verification.verify(action_id,mfa_code or '')
                if not verified.ok:
                    locked = security.note_fail(user_id,reason='mfa_invalid')
                    if locked or verified.code in ('attempts_exhausted','challenge_expired','challenge_missing'):
                        conn.execute("UPDATE pending_actions SET status='canceled' WHERE id=?",(action_id,))
                    audit.log(user_id,'user','mfa_fail',{'action_id':action_id},{'code':verified.code},'red')
                    return fail(verified.code,'验证码错误或已过期。',mfa_retry=not locked and verified.attempts_remaining > 0,
                                attempts_remaining=verified.attempts_remaining,locked=locked)
                authenticated_counter = verified.accepted_counter
                security.note_success(user_id,category='mfa')
            changed = conn.execute("UPDATE pending_actions SET status='executing' WHERE id=? AND status='pending'",(action_id,)).rowcount
            if changed != 1:
                return fail('already_processed','该操作已处理过。')
            result = tools.TOOLS[name](user_id,args)
            conn.execute("UPDATE pending_actions SET status='executed',executed_at=? WHERE id=?",(now().isoformat(),action_id))
            audit.log(user_id,'user','execute_action',{'action_id':action_id,'tool':name,'args':args},result,row['risk_level'])
        return {'executed':True,'result':result,'tool':name,'code':'executed'}
    except tools.ToolError as exc:
        # The debit, status, MFA consumption and receipt all rolled back together.
        with transaction() as conn:
            if authenticated_counter is not None:
                conn.execute('INSERT INTO mfa_totp_counters(user_id,counter) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET counter=MAX(counter,excluded.counter)',(user_id,authenticated_counter))
            conn.execute("UPDATE pending_actions SET status='failed' WHERE id=? AND status='pending'",(action_id,))
            audit.log(user_id,'tool','execution_failed',{'action_id':action_id},{'error':str(exc)},snapshot['risk_level'])
        return fail('business_error',f'操作失败：{exc}')

    except Exception:
        if authenticated_counter is not None:
            with transaction() as conn:
                conn.execute('INSERT INTO mfa_totp_counters(user_id,counter) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET counter=MAX(counter,excluded.counter)',(user_id,authenticated_counter))
        raise
