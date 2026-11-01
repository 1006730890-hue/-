"""Signed, typed slots from human messages; generic history never grants authority."""
import hashlib
import hmac
import json
import re
from datetime import datetime,timedelta,timezone
from .. import config,audit
from ..db import db,transaction
from .confirmation import _key


def _signature(state):
    return hmac.new(_key(),json.dumps(state,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()


def resolve(user_id,conversation_id,message):
    with db() as conn:
        row = conn.execute('SELECT clarification_state FROM conversations WHERE id=? AND user_id=?',(conversation_id,user_id)).fetchone()
        conn.execute('UPDATE conversations SET clarification_state=NULL WHERE id=? AND user_id=?',(conversation_id,user_id))
    if not row or not row['clarification_state']:
        return message,[]
    signed = json.loads(row['clarification_state'])
    state,signature = signed['state'],signed['signature']
    if not hmac.compare_digest(_signature(state),signature):
        return message,[]
    if state['user_id'] != user_id or state['conversation_id'] != conversation_id or datetime.fromisoformat(state['expires_at'])<=datetime.now(timezone.utc):
        return message,[]
    amount = re.fullmatch(r'\s*(?:那就|就)?\s*(\d+(?:\.\d{1,2})?)\s*(?:元|块)[。！!\s]*',message)
    if state['operation'] != 'transfer' or not amount:
        return message,[]
    composed = f"给{state['recipient']}转{amount.group(1)}元"
    sources = [{'role':'user','content':state['original_message'],'fields':['operation','recipient']},
               {'role':'user','content':message,'fields':['amount']}]
    audit.log(user_id,'duplex','authorization_slots',{'conversation_id':conversation_id},{'sources':sources,'composed_root':composed},'green')
    return composed,sources


def remember(user_id,conversation_id,message,response,request_id=None):
    if response.get('code') != 'clarification_required':
        return
    match = re.fullmatch(r'\s*(?:请|帮我|请帮我)?\s*(?:给|向)([\u4e00-\u9fffA-Za-z]{1,30}?)(?:转账|转|汇款)[。！!\s]*',message)
    if not match:
        return
    state = {'user_id':user_id,'conversation_id':conversation_id,'operation':'transfer',
             'recipient':match.group(1),'original_message':message,
             'expires_at':(datetime.now(timezone.utc)+timedelta(seconds=config.settings.CONFIRM_TTL_SECONDS)).isoformat()}
    value = json.dumps({'state':state,'signature':_signature(state)},ensure_ascii=False)
    with transaction() as conn:
        current = conn.execute('SELECT active_request FROM conversations WHERE id=? AND user_id=?',(conversation_id,user_id)).fetchone()
        if request_id and (not current or current['active_request'] != request_id):
            return
        conn.execute('UPDATE conversations SET clarification_state=? WHERE id=? AND user_id=?',(value,conversation_id,user_id))
    response['reply'] = f"请补充转给{state['recipient']}的金额（元）。您也可以重新完整说明业务，或发送“取消”。"
