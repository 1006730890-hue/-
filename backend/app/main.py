"""FastAPI 入口：对话、确认、审计查询、账户总览。"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
import os

from . import agent, audit, llm_client, conversation, customer_auth, config
from .config import settings
from .branding import PRODUCT_NAME, SECURITY_ID, SECURITY_NAME
from .db import db, init_db
from .seed import seed
from .admin_api import router as admin_router
from .admin_seed import seed_admin_data

app = FastAPI(title=PRODUCT_NAME, version="2.0.0")
app.include_router(admin_router)

app.add_middleware(
    CORSMiddleware, allow_origins=["http://127.0.0.1:8018", "http://localhost:8018", "http://127.0.0.1:5173", "http://localhost:5173"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)


class ChatReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(..., min_length=1, max_length=4000)
    conversation_id: Optional[str] = Field(None, max_length=64)
    user_token: str = "guest001"


class ConfirmReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    conversation_id: Optional[str] = Field(None, max_length=64)
    action_id: int = Field(..., gt=0, strict=True)
    approved: bool
    mfa_code: Optional[str] = None
    user_token: str = "guest001"


def _user_id(token: str) -> int:
    uid = customer_auth.resolve(token)
    if uid is None:
        raise HTTPException(401, '身份认证失败')
    return uid


@app.on_event("startup")
def startup():
    init_db()
    with db() as conn:
        has_users = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if not has_users:
        seed()
    seed_admin_data()
    customer_auth.initialize()


@app.get("/health")
def health():
    return {"status": "running", "llm_online": llm_client.is_available(),
            "model": config.settings.LLM_MODEL, "application": "bank-agent-duplex", "name": PRODUCT_NAME, "pid": os.getpid(), "instance_id": os.getenv("BANK_INSTANCE_ID", ""),
            "safety": {"framework": SECURITY_ID, "framework_name": SECURITY_NAME, "mode": config.settings.DUPLEX_MODE,
                       "detector": "external_configured" if config.settings.DUPLEX_DETECTOR_URL else "local_rules",
                       "mfa_delivery": "demo" if config.settings.DEMO_MODE else config.settings.MFA_PROVIDER,
                       "settlement": "local_ledger"}}


@app.post("/api/chat")
def chat(req: ChatReq):
    uid = _user_id(req.user_token)
    try:
        cid = conversation.ensure(req.conversation_id,uid)
    except ValueError as exc:
        raise HTTPException(403,str(exc)) from exc
    import uuid
    request_id = uuid.uuid4().hex
    with db() as conn:
        conn.execute('UPDATE conversations SET active_request=? WHERE id=? AND user_id=?',(request_id,cid,uid))
    from .duplex import clarification
    effective_message, authorization_sources = clarification.resolve(uid,cid,req.message)
    history = conversation.history(cid,uid)
    conversation.add_message(cid,uid,'user',req.message)
    task_id = conversation.create_task(cid,uid,req.message)
    result = agent.run(uid,effective_message,history,cid,request_id)
    clarification.remember(uid,cid,req.message,result,request_id)
    conversation.add_message(cid,uid,'assistant',result.get('reply',''))
    if result.get('needs_confirm'):
        conversation.bind_pending_action(result['confirm']['action_id'],task_id,uid)
        status = 'waiting_mfa' if result['confirm']['mfa_required'] else 'waiting_confirmation'
    else:
        status = 'failed' if result.get('blocked') or result.get('code') == 'business_error' else 'succeeded'
    conversation.update_task(task_id,uid,status,result)
    result.update(conversation_id=cid,task_id=task_id)
    return result


@app.post("/api/confirm")
def confirm(req: ConfirmReq):
    uid = _user_id(req.user_token)
    result = agent.confirm_action(uid,req.action_id,req.approved,req.mfa_code,req.conversation_id)
    conversation.finalize_pending_task(req.action_id,uid,result)
    return result


@app.get("/api/overview")
def overview(token: str = "guest001"):
    uid = _user_id(token)
    with db() as conn:
        acc = conn.execute("SELECT * FROM accounts WHERE user_id=?", (uid,)).fetchone()
        cards = [dict(r) for r in conn.execute("SELECT * FROM cards WHERE user_id=?", (uid,)).fetchall()]
        subs = [dict(r) for r in conn.execute(
            "SELECT * FROM subscriptions WHERE user_id=? AND status='active'", (uid,)).fetchall()]
        goals = [dict(r) for r in conn.execute(
            "SELECT * FROM goals WHERE user_id=? AND status='active'", (uid,)).fetchall()]
    return {"balance": acc["balance"], "account_no": acc["account_no"],
            "cards": cards, "subscriptions": subs, "goals": goals}


@app.get("/api/audit")
def view_audit(token: str = "guest001", limit: int = 30):
    uid = _user_id(token)
    return {"logs": audit.list_logs(uid, limit)}


class TaskActionReq(BaseModel):
    action: str
    user_token: str = 'guest001'
    reason: Optional[str] = None


class MemoryReq(BaseModel):
    model_config = ConfigDict(extra='forbid')
    content: str = Field(...,min_length=1,max_length=4000)
    user_token: str = 'guest001'
    conversation_id: Optional[str] = None


@app.get('/api/tasks')
def tasks(conversation_id: str,token: str='guest001'):
    return {'tasks':conversation.list_tasks(conversation_id,_user_id(token))}


@app.get('/api/tasks/{task_id}')
def task(task_id: str,token: str='guest001'):
    found = conversation.get_task(task_id,_user_id(token))
    if not found:
        raise HTTPException(404,'任务不存在')
    return found


@app.post('/api/tasks/{task_id}/action')
def task_action(task_id: str,req: TaskActionReq):
    try:
        return conversation.transition_task(task_id,_user_id(req.user_token),req.action,req.reason)
    except conversation.TaskTransitionError as exc:
        raise HTTPException(409,str(exc)) from exc


@app.get('/api/security/status')
def security_status(token: str='guest001'):
    _user_id(token)
    return {'framework':SECURITY_ID,'framework_name':SECURITY_NAME,'mode':config.settings.DUPLEX_MODE,
            'input_detector':'external_configured' if config.settings.DUPLEX_DETECTOR_URL else 'local_rules',
            'argument_scanner':'external_configured' if config.settings.DUPLEX_COMPONENT_URL else 'schema_and_local_rules',
            'memory_gate':'external_configured' if config.settings.DUPLEX_MEMORY_URL else 'local_isolated_memory',
            'dynamic_validator':'model_when_available', 'confirmation':'sealed_atomic',
            'audit_chain':audit.verify_chain(), 'settlement':'local_ledger',
            'mfa_delivery':'demo' if config.settings.DEMO_MODE else config.settings.MFA_PROVIDER}


@app.get('/api/security/runs/{run_id}')
def security_run(run_id: str,token: str='guest001'):
    uid = _user_id(token)
    with db() as conn:
        row = conn.execute('SELECT * FROM duplex_runs WHERE id=? AND user_id=?',(run_id,uid)).fetchone()
    if not row:
        raise HTTPException(404,'安全运行记录不存在')
    import json
    result = dict(row)
    for key in ('plan','evidence'):
        result[key] = json.loads(result[key])
    return result


@app.post('/api/memory')
def write_memory(req: MemoryReq):
    from .duplex.memory import add
    uid = _user_id(req.user_token)
    try:
        cid = conversation.ensure(req.conversation_id,uid)
    except ValueError as exc:
        raise HTTPException(403,str(exc)) from exc
    return add(uid,cid,req.content)


@app.get('/api/reports/spending.csv')
def spending_csv(months: int=12,token: str='guest001'):
    import csv
    import io
    from fastapi.responses import Response
    from . import tools
    from .duplex.kernel import TurnGuard
    uid = _user_id(token)
    guard = TurnGuard(uid,f'导出最近{months}个月消费报告')
    checked = guard.check('spending_report',{'months':months})
    if checked['decision'] != 'allow':
        raise HTTPException(400,checked.get('reason','参数错误'))
    try:
        report = tools.spending_report(uid,checked['args'])
    except tools.ToolError as exc:
        raise HTTPException(400,str(exc)) from exc
    safe = guard.isolate('spending_report',report)
    if not safe.get('ok'):
        raise HTTPException(503,'报告未通过安全检查')
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(['月份','支出（元）'])
    for row in safe['monthly_trend']:
        writer.writerow([row['month'],row['expense']])
    writer.writerow([])
    writer.writerow(['分类','金额（元）','占比'])
    for row in safe['category_ranking']:
        category = row['category']
        if category.lstrip().startswith(('=','+','-','@')):
            category = "'"+category
        writer.writerow([category,row['amount'],row['share']])
    guard.finish({'reply':'消费报告已导出。'})
    return Response(('\ufeff'+output.getvalue()).encode('utf-8'),media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition':'attachment; filename="spending-report.csv"'})


@app.middleware('http')
async def customer_token_context(request: Request,call_next):
    header = request.headers.get('Authorization','')
    token = header[7:] if header.startswith('Bearer ') else ''
    context = customer_auth.request_token.set(token)
    try:
        if request.url.path.startswith('/api/admin') and not config.settings.DEMO_MODE:
            from fastapi.responses import JSONResponse
            return JSONResponse({'detail':'旧管理台当前处于兼容模式；请使用客户业务界面的安全审计。'},status_code=403)
        return await call_next(request)
    finally:
        customer_auth.request_token.reset(context)


class LoginReq(BaseModel):
    model_config = ConfigDict(extra='forbid')
    login_name: str = Field(...,min_length=1,max_length=100)
    password: str = Field(...,min_length=1,max_length=200)


@app.post('/api/auth/login')
def customer_login(req: LoginReq):
    result = customer_auth.login(req.login_name,req.password)
    if not result['ok']:
        raise HTTPException(401,result['reply'])
    return result


@app.post('/api/auth/logout')
def customer_logout():
    customer_auth.logout('')
    return {'ok':True}


_dist = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
_admin_dist = os.path.join(os.path.dirname(__file__), "..", "..", "后台", "dist")
if os.path.isdir(_admin_dist):
    app.mount("/admin", StaticFiles(directory=_admin_dist, html=True), name="admin_static")
if os.path.isdir(_dist):
    app.mount("/", StaticFiles(directory=_dist, html=True), name="static")
