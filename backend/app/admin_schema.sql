-- Idempotent admin schema; contains no customer data.
CREATE TABLE IF NOT EXISTS agent_tasks(
    id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, user_id INTEGER NOT NULL,
    title TEXT NOT NULL, status TEXT DEFAULT 'running', created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
, review_reason TEXT);

CREATE TABLE IF NOT EXISTS organizations(
    id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    parent_id TEXT, level TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'enabled'
);

CREATE TABLE IF NOT EXISTS admin_roles(
    id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '', read_only INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS admin_permissions(
    id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT 'green'
);

CREATE TABLE IF NOT EXISTS admin_users(
    id TEXT PRIMARY KEY, login_name TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
    organization_id TEXT NOT NULL, data_scope TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'enabled', created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_user_roles(
    admin_id TEXT NOT NULL, role_id TEXT NOT NULL,
    PRIMARY KEY(admin_id,role_id)
);

CREATE TABLE IF NOT EXISTS admin_role_permissions(
    role_id TEXT NOT NULL, permission_id TEXT NOT NULL,
    PRIMARY KEY(role_id,permission_id)
);

CREATE TABLE IF NOT EXISTS admin_sessions(
    id TEXT PRIMARY KEY, admin_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS admin_approval_requests(
    id TEXT PRIMARY KEY, request_type TEXT NOT NULL, requester_id TEXT NOT NULL,
    organization_id TEXT NOT NULL, payload TEXT NOT NULL, payload_hash TEXT NOT NULL,
    reason TEXT NOT NULL, risk_level TEXT NOT NULL DEFAULT 'red',
    status TEXT NOT NULL DEFAULT 'PENDING', approver_id TEXT, decision_reason TEXT,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT,
    executed_at TEXT, result TEXT
);

CREATE TABLE IF NOT EXISTS admin_audit_logs(
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, admin_id TEXT, organization_id TEXT,
    action TEXT NOT NULL, resource_type TEXT, resource_id TEXT, params TEXT NOT NULL,
    result TEXT NOT NULL, risk_level TEXT NOT NULL, outcome TEXT NOT NULL,
    previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_events(
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, event_type TEXT NOT NULL,
    severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', evidence TEXT NOT NULL DEFAULT '{}',
    assignee_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS human_review_queue(
    id TEXT PRIMARY KEY, task_id TEXT, organization_id TEXT NOT NULL,
    reason_code TEXT NOT NULL, summary TEXT NOT NULL, customer_masked TEXT,
    status TEXT NOT NULL DEFAULT 'open', claimed_by TEXT, claimed_at TEXT,
    resolution TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
