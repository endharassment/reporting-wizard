-- Users (reporters and admins)
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    is_admin    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sessions for auth
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Magic link tokens
CREATE TABLE IF NOT EXISTS magic_links (
    token       TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- A report targets a single domain
CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id),
    domain          TEXT NOT NULL,
    urls            TEXT NOT NULL,
    violation_type  TEXT NOT NULL,
    description     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft',
    cloudflare_origin_ip TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Infrastructure discovered for a report's domain
CREATE TABLE IF NOT EXISTS infra_results (
    id              TEXT PRIMARY KEY,
    report_id       TEXT NOT NULL REFERENCES reports(id),
    ip              TEXT NOT NULL,
    record_type     TEXT NOT NULL,
    asn             INTEGER,
    asn_name        TEXT NOT NULL DEFAULT '',
    bgp_prefix      TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    abuse_contact   TEXT NOT NULL DEFAULT '',
    is_cloudflare   INTEGER NOT NULL DEFAULT 0,
    upstream_asns   TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Evidence files attached to a report
CREATE TABLE IF NOT EXISTS evidence (
    id              TEXT PRIMARY KEY,
    report_id       TEXT NOT NULL REFERENCES reports(id),
    filename        TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Every outgoing email (initial reports + escalations)
CREATE TABLE IF NOT EXISTS outgoing_emails (
    id              TEXT PRIMARY KEY,
    report_id       TEXT NOT NULL REFERENCES reports(id),
    parent_email_id TEXT REFERENCES outgoing_emails(id),
    recipient       TEXT NOT NULL,
    recipient_org   TEXT NOT NULL DEFAULT '',
    target_asn      INTEGER,
    email_type      TEXT NOT NULL,
    xarf_json       TEXT NOT NULL,
    email_subject   TEXT NOT NULL,
    email_body      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending_approval',
    approved_by     TEXT REFERENCES users(id),
    approved_at     TEXT,
    sent_at         TEXT,
    sendgrid_id     TEXT,
    escalate_after  TEXT,
    response_notes  TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Audit log for admin actions
CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    action      TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_infra_results_report_id ON infra_results(report_id);
CREATE INDEX IF NOT EXISTS idx_evidence_report_id ON evidence(report_id);
CREATE INDEX IF NOT EXISTS idx_outgoing_emails_report_id ON outgoing_emails(report_id);
CREATE INDEX IF NOT EXISTS idx_outgoing_emails_status ON outgoing_emails(status);
CREATE INDEX IF NOT EXISTS idx_outgoing_emails_escalate ON outgoing_emails(status, escalate_after);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
