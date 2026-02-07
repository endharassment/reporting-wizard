-- Add evidence_url column for cloud-hosted evidence links.
-- Make storage_path/sha256/size_bytes optional (they were required for file uploads).
ALTER TABLE evidence ADD COLUMN evidence_url TEXT NOT NULL DEFAULT '';

-- URL snapshots: text-only crawl of reported URLs for evidentiary purposes.
CREATE TABLE IF NOT EXISTS url_snapshots (
    id          TEXT PRIMARY KEY,
    report_id   TEXT NOT NULL REFERENCES reports(id),
    url         TEXT NOT NULL,
    text_content TEXT NOT NULL DEFAULT '',
    fetched_at  TEXT NOT NULL DEFAULT (datetime('now')),
    error       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_url_snapshots_report_id ON url_snapshots(report_id);
