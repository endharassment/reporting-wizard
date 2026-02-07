CREATE TABLE IF NOT EXISTS email_replies (
    id TEXT PRIMARY KEY,
    outgoing_email_id TEXT NOT NULL,
    from_address TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (outgoing_email_id) REFERENCES outgoing_emails(id) ON DELETE CASCADE
);
