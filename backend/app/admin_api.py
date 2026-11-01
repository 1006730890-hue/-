from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from typing import Any

from . import admin_audit, admin_auth, admin_service
from .admin_seed import ADMINS, ROLES

router = APIRouter(prefix="/api/admin", tags=["admin"])

class LoginReq(BaseModel): login_name: str
class ApprovalReq(BaseModel): request_type: str; payload: dict[str, Any]; reason: str
class DecisionReq(BaseModel): approved: bool; reason: str

def _token(authorization):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "管理员会话缺失")
    return authorization[7:]

def context(authorization: str | None = Header(default=None)):
    try: return admin_auth.authenticate(_token(authorization))
    except admin_auth.AuthenticationError as exc: raise HTTPException(401, str(exc)) from exc

def _run(fn, *args):
    try: return fn(*args)
    except admin_auth.PermissionDenied as exc: raise HTTPException(403, str(exc)) from exc
    except admin_service.NotFound as exc: raise HTTPException(404, str(exc)) from exc
    except admin_service.Conflict as exc: raise HTTPException(409, str(exc)) from exc
    except admin_service.InvalidRequest as exc: raise HTTPException(422, str(exc)) from exc

def _me(ctx):
    return {"id": ctx.admin_id, "login_name": ctx.login_name, "display_name": ctx.display_name,
            "organization_id": ctx.organization_id, "organization_name": ctx.organization_name,
            "data_scope": ctx.data_scope, "roles": ctx.roles, "permissions": sorted(ctx.permissions)}

@router.get("/auth/demo-accounts")
def demo_accounts():
    return {"accounts": [{"login_name": a[1], "display_name": a[2], "organization_id": a[3], "data_scope": a[4], "role": ROLES[a[5]][0]} for a in ADMINS]}

@router.post("/auth/demo-login")
def login(req: LoginReq):
    try:
        result = admin_auth.demo_login(req.login_name); result["admin"] = _me(result["admin"]); return result
    except admin_auth.AuthenticationError as exc: raise HTTPException(401, str(exc)) from exc

@router.get("/me")
def me(authorization: str | None = Header(default=None)): return _me(context(authorization))

@router.get("/dashboard")
def dashboard(authorization: str | None = Header(default=None)): return _run(admin_service.dashboard, context(authorization))

@router.get("/reviews")
def reviews(authorization: str | None = Header(default=None)): return {"items": _run(admin_service.list_reviews, context(authorization))}

@router.post("/reviews/{review_id}/claim")
def claim(review_id: str, authorization: str | None = Header(default=None)): return _run(admin_service.claim_review, context(authorization), review_id)

@router.get("/risk-events")
def risks(authorization: str | None = Header(default=None)): return {"items": _run(admin_service.list_risks, context(authorization))}

@router.get("/approvals")
def approvals(authorization: str | None = Header(default=None)): return {"items": _run(admin_service.list_approvals, context(authorization))}

@router.post("/approvals")
def create_approval(req: ApprovalReq, authorization: str | None = Header(default=None)): return _run(admin_service.create_approval, context(authorization), req.request_type, req.payload, req.reason)

@router.post("/approvals/{request_id}/decision")
def decide(request_id: str, req: DecisionReq, authorization: str | None = Header(default=None)): return _run(admin_service.decide_approval, context(authorization), request_id, req.approved, req.reason)

@router.get("/audit")
def audit_logs(authorization: str | None = Header(default=None)):
    ctx=context(authorization); _run(admin_auth.require_permission, ctx, "audit.read"); return {"items": admin_audit.list_logs()}

@router.get("/audit/verify")
def audit_verify(authorization: str | None = Header(default=None)):
    ctx=context(authorization); _run(admin_auth.require_permission, ctx, "audit.verify"); return admin_audit.verify_chain()
