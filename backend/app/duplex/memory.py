"""User-scoped, low-trust persistent memory. Memory never grants tool authority."""
import json
from .. import config, audit
from ..db import db
from .detection import inspect_input, detector, post
from .drift_runtime import InjectionIsolator


def add(user_id, conversation_id, content):
    checked = inspect_input(content)
    trust = 'quarantined' if checked['decision'] != 'allow' else 'untrusted'
    with db() as conn:
        cur = conn.execute("INSERT INTO duplex_memories(user_id,conversation_id,content,trust,created_at) VALUES(?,?,?,?,datetime('now'))",
                           (user_id,conversation_id,content,trust))
    if trust != 'quarantined' and config.settings.DUPLEX_MEMORY_URL:
        remote = post(config.settings.DUPLEX_MEMORY_URL,'/memory/write',
                      {'content':content,'source_type':'external_web_content','source_id':f'local-{cur.lastrowid}',
                       'session_id':f'user-{user_id}','metadata':{'user_id':user_id}})
        if remote.get('available') is False:
            raise RuntimeError('memory service did not accept the record')
    audit.log(user_id,'duplex','memory_write',{'memory_id':cur.lastrowid},{'trust':trust},'red' if trust == 'quarantined' else 'green')
    return {'id':cur.lastrowid,'trust':trust,'source':'local_memory'}


def recall(user_id, query, conversation_id):
    url = config.settings.DUPLEX_MEMORY_URL
    if url:
        # Session scope is mandatory. Do not silently retry using a global shared memory pool.
        body = post(url,'/memory/read',{'query':query,'k':5,'privileged':False,
                                      'session_id':f'user-{user_id}'})
        if body.get('available') is not True or not isinstance(body.get('kept'),list) or body.get('decision') in ('deny','unavailable'):
            raise RuntimeError('memory trust service unavailable')
        raw = [r for r in body['kept'] if r.get('session_id',r.get('metadata',{}).get('session_id')) == f'user-{user_id}']
    elif config.settings.DUPLEX_MODE == 'external_required':
        raise RuntimeError('required memory service not configured')
    else:
        with db() as conn:
            raw = [dict(r) for r in conn.execute("SELECT id,content,trust FROM duplex_memories WHERE user_id=? AND trust='untrusted' ORDER BY id DESC LIMIT 5",(user_id,))]
    safe = InjectionIsolator(detector).isolate(raw,tool_name='memory_recall')
    audit.log(user_id,'duplex','memory_read',{'conversation_id':conversation_id},
              {'detected':safe.detected,'quarantined':safe.quarantined,'digest':safe.envelope.content_hash},'green')
    return [] if safe.quarantined else json.loads(safe.safe_content)
