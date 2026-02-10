CREATE TABLE IF NOT EXISTS invites (
    id         TEXT PRIMARY KEY,
    code       TEXT UNIQUE NOT NULL,
    email      TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    used_by    TEXT REFERENCES users(id),
    max_uses   INTEGER NOT NULL DEFAULT 1,
    use_count  INTEGER NOT NULL DEFAULT 0,
    revoked    INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invites_code ON invites(code);
