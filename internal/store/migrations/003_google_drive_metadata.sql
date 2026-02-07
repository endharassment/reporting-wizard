-- Store Google OAuth tokens on users for Drive API access.
ALTER TABLE users ADD COLUMN google_access_token TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN google_refresh_token TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN google_token_expiry TEXT NOT NULL DEFAULT '';

-- Store Google Drive metadata on evidence records.
ALTER TABLE evidence ADD COLUMN drive_file_id TEXT NOT NULL DEFAULT '';
ALTER TABLE evidence ADD COLUMN drive_file_name TEXT NOT NULL DEFAULT '';
ALTER TABLE evidence ADD COLUMN drive_mime_type TEXT NOT NULL DEFAULT '';
ALTER TABLE evidence ADD COLUMN drive_size INTEGER NOT NULL DEFAULT 0;
ALTER TABLE evidence ADD COLUMN drive_verified INTEGER NOT NULL DEFAULT 0;
