"""Idempotent administrator, RBAC, organization, and operations demo fixtures."""
from datetime import datetime, timezone

from .db import db, init_db


ORGANIZATIONS = [
    ("org-hq", "HQ", "微众银行总行", None, "head_office"),
    ("org-sz", "SZ", "深圳分行", "org-hq", "branch"),
    ("org-sz-ns", "SZ-NS", "南山支行", "org-sz", "outlet"),
    ("org-sz-ft", "SZ-FT", "福田支行", "org-sz", "outlet"),
    ("org-gz", "GZ", "广州分行", "org-hq", "branch"),
    ("org-gz-th", "GZ-TH", "天河支行", "org-gz", "outlet"),
    ("org-gz-yx", "GZ-YX", "越秀支行", "org-gz", "outlet"),
]

PERMISSIONS = {
    "dashboard.read": ("查看运营看板", "green"),
    "agent_tasks.read": ("查看 Agent 任务", "green"),
    "agent_tasks.pause": ("控制 Agent 任务", "yellow"),
    "human_reviews.read": ("查看人工接管", "green"),
    "human_reviews.claim": ("认领人工任务", "yellow"),
    "human_reviews.decide": ("完成人工任务", "yellow"),
    "risk_events.read": ("查看风险事件", "green"),
    "risk_events.manage": ("处置风险事件", "yellow"),
    "customer_summary.read": ("查看脱敏客户摘要", "green"),
    "customer_sensitive.read": ("查看完整敏感信息", "red"),
    "approvals.read": ("查看审批", "green"),
    "approvals.create": ("发起审批", "red"),
    "approvals.decide": ("审批高风险操作", "red"),
    "audit.read": ("查看管理员审计", "green"),
    "audit.verify": ("校验管理员审计链", "green"),
    "audit.export": ("导出管理员审计", "red"),
    "admins.read": ("查看管理员", "green"),
    "admins.manage": ("变更管理员", "red"),
    "policies.read": ("查看安全策略", "green"),
    "policies.change": ("修改安全策略", "red"),
    "systems.read": ("查看技术状态", "green"),
}

ROLES = {
    "observer": ("运营观察员", "查看全行聚合运营指标", 1, {"dashboard.read", "systems.read"}),
    "service": ("客服专员", "处理本机构人工接管任务", 0, {"dashboard.read", "agent_tasks.read", "human_reviews.read", "human_reviews.claim", "human_reviews.decide", "customer_summary.read"}),
    "risk": ("风控专员", "调查和处置机构范围风险", 0, {"dashboard.read", "agent_tasks.read", "risk_events.read", "risk_events.manage", "customer_summary.read", "approvals.read", "approvals.create"}),
    "reviewer": ("业务审核员", "复核高风险管理操作", 0, {"dashboard.read", "approvals.read", "approvals.decide", "audit.read"}),
    "auditor": ("审计员", "只读审计与完整性验证", 1, {"dashboard.read", "approvals.read", "audit.read", "audit.verify", "audit.export", "admins.read"}),
    "security": ("安全管理员", "管理账号、角色与安全策略", 0, {"dashboard.read", "risk_events.read", "risk_events.manage", "approvals.read", "approvals.create", "admins.read", "admins.manage", "policies.read", "policies.change", "audit.read", "audit.verify"}),
    "system": ("系统管理员", "维护服务和模型，不具备业务资金权限", 0, {"dashboard.read", "systems.read", "audit.read"}),
}

ADMINS = [
    ("adm-observer", "observer", "运营观察员", "org-hq", "GLOBAL", "observer"),
    ("adm-service-ns", "service_nanshan", "南山客服专员", "org-sz-ns", "BRANCH", "service"),
    ("adm-risk-sz", "risk_shenzhen", "深圳风控专员", "org-sz", "SUBTREE", "risk"),
    ("adm-reviewer", "reviewer_hq", "总行业务审核员", "org-hq", "GLOBAL", "reviewer"),
    ("adm-auditor", "auditor_hq", "总行审计员", "org-hq", "GLOBAL", "auditor"),
    ("adm-security", "security_hq", "总行安全管理员", "org-hq", "GLOBAL", "security"),
    ("adm-system", "system_hq", "总行系统管理员", "org-hq", "GLOBAL", "system"),
]


def seed_admin_data():
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        for row in ORGANIZATIONS:
            conn.execute(
                """INSERT INTO organizations(id,code,name,parent_id,level)
                   VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                   code=excluded.code,name=excluded.name,parent_id=excluded.parent_id,
                   level=excluded.level""", row,
            )
        for code, (name, risk) in PERMISSIONS.items():
            conn.execute(
                """INSERT INTO admin_permissions(id,code,name,risk_level)
                   VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                   name=excluded.name,risk_level=excluded.risk_level""",
                (f"perm-{code}", code, name, risk),
            )
        for code, (name, description, read_only, permissions) in ROLES.items():
            role_id = f"role-{code}"
            conn.execute(
                """INSERT INTO admin_roles(id,code,name,description,read_only)
                   VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                   name=excluded.name,description=excluded.description,
                   read_only=excluded.read_only""",
                (role_id, code, name, description, read_only),
            )
            for permission in permissions:
                conn.execute(
                    """INSERT INTO admin_role_permissions(role_id,permission_id)
                       VALUES(?,?) ON CONFLICT(role_id,permission_id) DO NOTHING""",
                    (role_id, f"perm-{permission}"),
                )
        for admin_id, login, display, org, scope, role in ADMINS:
            conn.execute(
                """INSERT INTO admin_users(
                       id,login_name,display_name,organization_id,data_scope,status,created_at
                   ) VALUES(?,?,?,?,?,'enabled',?) ON CONFLICT(id) DO UPDATE SET
                   login_name=excluded.login_name,display_name=excluded.display_name,
                   organization_id=excluded.organization_id,data_scope=excluded.data_scope""",
                (admin_id, login, display, org, scope, now),
            )
            conn.execute(
                """INSERT INTO admin_user_roles(admin_id,role_id) VALUES(?,?)
                   ON CONFLICT(admin_id,role_id) DO NOTHING""",
                (admin_id, f"role-{role}"),
            )

        fixtures = [
            ("risk-injection", "org-sz-ns", "prompt_injection", "high", "提示词注入已阻断", "客户请求绕过验证码，已在模型调用前阻断"),
            ("risk-mfa", "org-sz-ft", "mfa_failure", "medium", "连续 MFA 失败", "同一客户两次验证码输入失败"),
            ("risk-anomaly", "org-gz-th", "transaction_anomaly", "high", "异常交易待核实", "境外交易金额显著高于个人基线"),
        ]
        for event_id, org, event_type, severity, title, description in fixtures:
            conn.execute(
                """INSERT INTO risk_events(
                       id,organization_id,event_type,severity,title,description,evidence,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?, ?,?) ON CONFLICT(id) DO NOTHING""",
                (event_id, org, event_type, severity, title, description, "{}", now, now),
            )
        reviews = [
            ("review-ns", "org-sz-ns", "recipient_disambiguation", "同名收款人需要人工协助", "张* / 138****0001"),
            ("review-ft", "org-sz-ft", "customer_request", "客户主动请求人工客服", "李* / 139****0018"),
            ("review-gz", "org-gz-th", "model_fallback", "模型降级后需人工复核", "王* / 136****0026"),
        ]
        for review_id, org, reason, summary, customer in reviews:
            conn.execute(
                """INSERT INTO human_review_queue(
                       id,organization_id,reason_code,summary,customer_masked,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING""",
                (review_id, org, reason, summary, customer, now, now),
            )
