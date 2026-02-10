package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	_ "modernc.org/sqlite"
)

const timeFormat = "2006-01-02 15:04:05"

// SQLiteStore implements Store backed by SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens a SQLite database at the given path and runs migrations.
func NewSQLiteStore(ctx context.Context, dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	s := &SQLiteStore{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	// Sort by filename to ensure order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		data, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		if _, err := s.db.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("execute migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// --- Users ---

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*model.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, name, is_admin, banned, google_access_token, google_refresh_token, google_token_expiry, created_at FROM users WHERE id = ?`, id))
}

func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, name, is_admin, banned, google_access_token, google_refresh_token, google_token_expiry, created_at FROM users WHERE email = ?`, email))
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, user *model.User) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email = ?, name = ?, is_admin = ?, google_access_token = ?, google_refresh_token = ?, google_token_expiry = ? WHERE id = ?`,
		user.Email, user.Name, boolToInt(user.IsAdmin),
		user.GoogleAccessToken, user.GoogleRefreshToken, nullTimeVal(user.GoogleTokenExpiry),
		user.ID)
	return err
}

func (s *SQLiteStore) BanUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET banned = 1 WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]*model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, email, name, is_admin, banned, google_access_token, google_refresh_token, google_token_expiry, created_at FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*model.User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func (s *SQLiteStore) CreateUser(ctx context.Context, user *model.User) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, is_admin, banned, google_access_token, google_refresh_token, google_token_expiry, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.Name, boolToInt(user.IsAdmin), boolToInt(user.Banned),
		user.GoogleAccessToken, user.GoogleRefreshToken, nullTimeVal(user.GoogleTokenExpiry),
		user.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) scanUser(row scannable) (*model.User, error) {
	var u model.User
	var isAdmin, banned int
	var createdAt, tokenExpiry string
	err := row.Scan(&u.ID, &u.Email, &u.Name, &isAdmin, &banned,
		&u.GoogleAccessToken, &u.GoogleRefreshToken, &tokenExpiry, &createdAt)
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.Banned = banned != 0
	u.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	if tokenExpiry != "" {
		u.GoogleTokenExpiry, _ = time.Parse(timeFormat, tokenExpiry)
	}
	return &u, nil
}

func nullTimeVal(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeFormat)
}

// --- Sessions ---

func (s *SQLiteStore) CreateSession(ctx context.Context, sess *model.Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.ExpiresAt.UTC().Format(timeFormat), sess.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*model.Session, error) {
	var sess model.Session
	var expiresAt, createdAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, expires_at, created_at FROM sessions WHERE id = ?`, id).
		Scan(&sess.ID, &sess.UserID, &expiresAt, &createdAt)
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt, _ = time.Parse(timeFormat, expiresAt)
	sess.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	return &sess, nil
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(timeFormat))
	return err
}

// --- Reports ---

func (s *SQLiteStore) CreateReport(ctx context.Context, report *model.Report) error {
	urlsJSON, err := json.Marshal(report.URLs)
	if err != nil {
		return fmt.Errorf("marshal urls: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO reports (id, user_id, domain, urls, violation_type, description, status, cloudflare_origin_ip, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.ID, report.UserID, report.Domain, string(urlsJSON),
		string(report.ViolationType), report.Description, string(report.Status),
		nullString(report.CloudflareOriginIP),
		report.CreatedAt.UTC().Format(timeFormat), report.UpdatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) GetReport(ctx context.Context, id string) (*model.Report, error) {
	return s.scanReport(s.db.QueryRowContext(ctx,
		`SELECT id, user_id, domain, urls, violation_type, description, status, cloudflare_origin_ip, created_at, updated_at
		 FROM reports WHERE id = ?`, id))
}

func (s *SQLiteStore) UpdateReport(ctx context.Context, report *model.Report) error {
	urlsJSON, err := json.Marshal(report.URLs)
	if err != nil {
		return fmt.Errorf("marshal urls: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE reports SET domain = ?, urls = ?, violation_type = ?, description = ?, status = ?,
		 cloudflare_origin_ip = ?, updated_at = ? WHERE id = ?`,
		report.Domain, string(urlsJSON), string(report.ViolationType), report.Description,
		string(report.Status), nullString(report.CloudflareOriginIP),
		time.Now().UTC().Format(timeFormat), report.ID)
	return err
}

func (s *SQLiteStore) ListReportsByUser(ctx context.Context, userID string) ([]*model.Report, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, domain, urls, violation_type, description, status, cloudflare_origin_ip, created_at, updated_at
		 FROM reports WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanReports(rows)
}

func (s *SQLiteStore) ListReportsByStatus(ctx context.Context, status model.ReportStatus) ([]*model.Report, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, domain, urls, violation_type, description, status, cloudflare_origin_ip, created_at, updated_at
		 FROM reports WHERE status = ? ORDER BY created_at DESC`, string(status))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanReports(rows)
}

func (s *SQLiteStore) scanReport(row *sql.Row) (*model.Report, error) {
	var r model.Report
	var urlsJSON, violationType, status, createdAt, updatedAt string
	var originIP sql.NullString
	err := row.Scan(&r.ID, &r.UserID, &r.Domain, &urlsJSON, &violationType, &r.Description,
		&status, &originIP, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(urlsJSON), &r.URLs)
	r.ViolationType = model.ViolationType(violationType)
	r.Status = model.ReportStatus(status)
	r.CloudflareOriginIP = originIP.String
	r.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	r.UpdatedAt, _ = time.Parse(timeFormat, updatedAt)
	return &r, nil
}

func (s *SQLiteStore) scanReports(rows *sql.Rows) ([]*model.Report, error) {
	var reports []*model.Report
	for rows.Next() {
		var r model.Report
		var urlsJSON, violationType, status, createdAt, updatedAt string
		var originIP sql.NullString
		err := rows.Scan(&r.ID, &r.UserID, &r.Domain, &urlsJSON, &violationType, &r.Description,
			&status, &originIP, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(urlsJSON), &r.URLs)
		r.ViolationType = model.ViolationType(violationType)
		r.Status = model.ReportStatus(status)
		r.CloudflareOriginIP = originIP.String
		r.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		r.UpdatedAt, _ = time.Parse(timeFormat, updatedAt)
		reports = append(reports, &r)
	}
	return reports, rows.Err()
}

// --- Infrastructure Results ---

func (s *SQLiteStore) CreateInfraResult(ctx context.Context, result *model.InfraResult) error {
	upstreamJSON, err := json.Marshal(result.UpstreamASNs)
	if err != nil {
		return fmt.Errorf("marshal upstream asns: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO infra_results (id, report_id, ip, record_type, asn, asn_name, bgp_prefix, country, abuse_contact, is_cloudflare, upstream_asns, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.ID, result.ReportID, result.IP, result.RecordType, result.ASN, result.ASNName,
		result.BGPPrefix, result.Country, result.AbuseContact, boolToInt(result.IsCloudflare),
		string(upstreamJSON), result.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) ListInfraResultsByReport(ctx context.Context, reportID string) ([]*model.InfraResult, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, report_id, ip, record_type, asn, asn_name, bgp_prefix, country, abuse_contact, is_cloudflare, upstream_asns, created_at
		 FROM infra_results WHERE report_id = ? ORDER BY created_at`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*model.InfraResult
	for rows.Next() {
		var r model.InfraResult
		var isCloudflare int
		var upstreamJSON, createdAt string
		err := rows.Scan(&r.ID, &r.ReportID, &r.IP, &r.RecordType, &r.ASN, &r.ASNName,
			&r.BGPPrefix, &r.Country, &r.AbuseContact, &isCloudflare, &upstreamJSON, &createdAt)
		if err != nil {
			return nil, err
		}
		r.IsCloudflare = isCloudflare != 0
		_ = json.Unmarshal([]byte(upstreamJSON), &r.UpstreamASNs)
		r.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		results = append(results, &r)
	}
	return results, rows.Err()
}

func (s *SQLiteStore) DeleteInfraResultsByReport(ctx context.Context, reportID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM infra_results WHERE report_id = ?`, reportID)
	return err
}

// --- Evidence ---

func (s *SQLiteStore) CreateEvidence(ctx context.Context, ev *model.Evidence) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO evidence (id, report_id, filename, content_type, storage_path, sha256, size_bytes, evidence_url, description, drive_file_id, drive_file_name, drive_mime_type, drive_size, drive_verified, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.ReportID, ev.Filename, ev.ContentType, ev.StoragePath,
		ev.SHA256, ev.SizeBytes, ev.EvidenceURL, ev.Description,
		ev.DriveFileID, ev.DriveFileName, ev.DriveMimeType, ev.DriveSize, boolToInt(ev.DriveVerified),
		ev.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) UpdateEvidence(ctx context.Context, ev *model.Evidence) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE evidence SET drive_file_id = ?, drive_file_name = ?, drive_mime_type = ?, drive_size = ?, drive_verified = ? WHERE id = ?`,
		ev.DriveFileID, ev.DriveFileName, ev.DriveMimeType, ev.DriveSize, boolToInt(ev.DriveVerified), ev.ID)
	return err
}

func (s *SQLiteStore) GetEvidence(ctx context.Context, id string) (*model.Evidence, error) {
	var ev model.Evidence
	var createdAt string
	var driveVerified int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, report_id, filename, content_type, storage_path, sha256, size_bytes, evidence_url, description,
		        drive_file_id, drive_file_name, drive_mime_type, drive_size, drive_verified, created_at
		 FROM evidence WHERE id = ?`, id).
		Scan(&ev.ID, &ev.ReportID, &ev.Filename, &ev.ContentType, &ev.StoragePath,
			&ev.SHA256, &ev.SizeBytes, &ev.EvidenceURL, &ev.Description,
			&ev.DriveFileID, &ev.DriveFileName, &ev.DriveMimeType, &ev.DriveSize, &driveVerified, &createdAt)
	if err != nil {
		return nil, err
	}
	ev.DriveVerified = driveVerified != 0
	ev.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	return &ev, nil
}

func (s *SQLiteStore) ListEvidenceByReport(ctx context.Context, reportID string) ([]*model.Evidence, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, report_id, filename, content_type, storage_path, sha256, size_bytes, evidence_url, description,
		        drive_file_id, drive_file_name, drive_mime_type, drive_size, drive_verified, created_at
		 FROM evidence WHERE report_id = ? ORDER BY created_at`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*model.Evidence
	for rows.Next() {
		var ev model.Evidence
		var createdAt string
		var driveVerified int
		err := rows.Scan(&ev.ID, &ev.ReportID, &ev.Filename, &ev.ContentType, &ev.StoragePath,
			&ev.SHA256, &ev.SizeBytes, &ev.EvidenceURL, &ev.Description,
			&ev.DriveFileID, &ev.DriveFileName, &ev.DriveMimeType, &ev.DriveSize, &driveVerified, &createdAt)
		if err != nil {
			return nil, err
		}
		ev.DriveVerified = driveVerified != 0
		ev.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		results = append(results, &ev)
	}
	return results, rows.Err()
}

// --- URL Snapshots ---

func (s *SQLiteStore) CreateURLSnapshot(ctx context.Context, snap *model.URLSnapshot) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO url_snapshots (id, report_id, url, text_content, fetched_at, error, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		snap.ID, snap.ReportID, snap.URL, snap.TextContent,
		snap.FetchedAt.UTC().Format(timeFormat), snap.Error,
		snap.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) ListURLSnapshotsByReport(ctx context.Context, reportID string) ([]*model.URLSnapshot, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, report_id, url, text_content, fetched_at, error, created_at
		 FROM url_snapshots WHERE report_id = ? ORDER BY created_at`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*model.URLSnapshot
	for rows.Next() {
		var snap model.URLSnapshot
		var fetchedAt, createdAt string
		err := rows.Scan(&snap.ID, &snap.ReportID, &snap.URL, &snap.TextContent,
			&fetchedAt, &snap.Error, &createdAt)
		if err != nil {
			return nil, err
		}
		snap.FetchedAt, _ = time.Parse(timeFormat, fetchedAt)
		snap.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		results = append(results, &snap)
	}
	return results, rows.Err()
}

// --- Outgoing Emails ---

func (s *SQLiteStore) CreateOutgoingEmail(ctx context.Context, email *model.OutgoingEmail) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO outgoing_emails (id, report_id, parent_email_id, recipient, recipient_org, target_asn, email_type, xarf_json, email_subject, email_body, status, escalate_after, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		email.ID, email.ReportID, nullString(email.ParentEmailID), email.Recipient, email.RecipientOrg,
		email.TargetASN, string(email.EmailType), email.XARFJson, email.EmailSubject, email.EmailBody,
		string(email.Status), nullTime(email.EscalateAfter), email.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) GetOutgoingEmail(ctx context.Context, id string) (*model.OutgoingEmail, error) {
	return s.scanEmail(s.db.QueryRowContext(ctx,
		`SELECT id, report_id, parent_email_id, recipient, recipient_org, target_asn, email_type,
		 xarf_json, email_subject, email_body, status, approved_by, approved_at, sent_at,
		 sendgrid_id, escalate_after, response_notes, created_at
		 FROM outgoing_emails WHERE id = ?`, id))
}

func (s *SQLiteStore) UpdateOutgoingEmail(ctx context.Context, email *model.OutgoingEmail) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE outgoing_emails SET status = ?, approved_by = ?, approved_at = ?, sent_at = ?,
		 sendgrid_id = ?, escalate_after = ?, response_notes = ? WHERE id = ?`,
		string(email.Status), nullString(email.ApprovedBy), nullTime(email.ApprovedAt),
		nullTime(email.SentAt), nullString(email.SendGridID), nullTime(email.EscalateAfter),
		nullString(email.ResponseNotes), email.ID)
	return err
}

func (s *SQLiteStore) ListEmailsByReport(ctx context.Context, reportID string) ([]*model.OutgoingEmail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, report_id, parent_email_id, recipient, recipient_org, target_asn, email_type,
		 xarf_json, email_subject, email_body, status, approved_by, approved_at, sent_at,
		 sendgrid_id, escalate_after, response_notes, created_at
		 FROM outgoing_emails WHERE report_id = ? ORDER BY created_at`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanEmails(rows)
}

func (s *SQLiteStore) ListEmailsByStatus(ctx context.Context, status model.EmailStatus) ([]*model.OutgoingEmail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, report_id, parent_email_id, recipient, recipient_org, target_asn, email_type,
		 xarf_json, email_subject, email_body, status, approved_by, approved_at, sent_at,
		 sendgrid_id, escalate_after, response_notes, created_at
		 FROM outgoing_emails WHERE status = ? ORDER BY created_at`, string(status))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanEmails(rows)
}

func (s *SQLiteStore) ListEmailsDueForEscalation(ctx context.Context, now time.Time) ([]*model.OutgoingEmail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, report_id, parent_email_id, recipient, recipient_org, target_asn, email_type,
		 xarf_json, email_subject, email_body, status, approved_by, approved_at, sent_at,
		 sendgrid_id, escalate_after, response_notes, created_at
		 FROM outgoing_emails WHERE status = 'sent' AND escalate_after IS NOT NULL AND escalate_after < ?
		 AND response_notes IS NULL
		 ORDER BY escalate_after`, now.UTC().Format(timeFormat))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanEmails(rows)
}

func (s *SQLiteStore) scanEmail(row *sql.Row) (*model.OutgoingEmail, error) {
	var e model.OutgoingEmail
	var parentID, emailType, status, approvedBy, sendgridID, responseNotes sql.NullString
	var approvedAt, sentAt, escalateAfter, createdAt sql.NullString
	var targetASN sql.NullInt64
	err := row.Scan(&e.ID, &e.ReportID, &parentID, &e.Recipient, &e.RecipientOrg, &targetASN,
		&emailType, &e.XARFJson, &e.EmailSubject, &e.EmailBody, &status, &approvedBy,
		&approvedAt, &sentAt, &sendgridID, &escalateAfter, &responseNotes, &createdAt)
	if err != nil {
		return nil, err
	}
	e.ParentEmailID = parentID.String
	e.TargetASN = int(targetASN.Int64)
	e.EmailType = model.EmailType(emailType.String)
	e.Status = model.EmailStatus(status.String)
	e.ApprovedBy = approvedBy.String
	e.ApprovedAt = parseNullTime(approvedAt)
	e.SentAt = parseNullTime(sentAt)
	e.SendGridID = sendgridID.String
	e.EscalateAfter = parseNullTime(escalateAfter)
	e.ResponseNotes = responseNotes.String
	if createdAt.Valid {
		e.CreatedAt, _ = time.Parse(timeFormat, createdAt.String)
	}
	return &e, nil
}

func (s *SQLiteStore) scanEmails(rows *sql.Rows) ([]*model.OutgoingEmail, error) {
	var emails []*model.OutgoingEmail
	for rows.Next() {
		var e model.OutgoingEmail
		var parentID, emailType, status, approvedBy, sendgridID, responseNotes sql.NullString
		var approvedAt, sentAt, escalateAfter, createdAt sql.NullString
		var targetASN sql.NullInt64
		err := rows.Scan(&e.ID, &e.ReportID, &parentID, &e.Recipient, &e.RecipientOrg, &targetASN,
			&emailType, &e.XARFJson, &e.EmailSubject, &e.EmailBody, &status, &approvedBy,
			&approvedAt, &sentAt, &sendgridID, &escalateAfter, &responseNotes, &createdAt)
		if err != nil {
			return nil, err
		}
		e.ParentEmailID = parentID.String
		e.TargetASN = int(targetASN.Int64)
		e.EmailType = model.EmailType(emailType.String)
		e.Status = model.EmailStatus(status.String)
		e.ApprovedBy = approvedBy.String
		e.ApprovedAt = parseNullTime(approvedAt)
		e.SentAt = parseNullTime(sentAt)
		e.SendGridID = sendgridID.String
		e.EscalateAfter = parseNullTime(escalateAfter)
		e.ResponseNotes = responseNotes.String
		if createdAt.Valid {
			e.CreatedAt, _ = time.Parse(timeFormat, createdAt.String)
		}
		emails = append(emails, &e)
	}
	return emails, rows.Err()
}

// --- Audit Log ---

func (s *SQLiteStore) CreateAuditLogEntry(ctx context.Context, entry *model.AuditLogEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, user_id, action, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.UserID, entry.Action, entry.TargetID, entry.Details,
		entry.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) ListAuditLogByTarget(ctx context.Context, targetID string) ([]*model.AuditLogEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, action, target_id, details, created_at FROM audit_log WHERE target_id = ? ORDER BY created_at DESC`,
		targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*model.AuditLogEntry
	for rows.Next() {
		var e model.AuditLogEntry
		var createdAt string
		err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.TargetID, &e.Details, &createdAt)
		if err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// --- Email Replies ---

func (s *SQLiteStore) CreateEmailReply(ctx context.Context, reply *model.EmailReply) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO email_replies (id, outgoing_email_id, from_address, body, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		reply.ID, reply.OutgoingEmailID, reply.FromAddress, reply.Body,
		reply.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) ListEmailRepliesByEmail(ctx context.Context, emailID string) ([]*model.EmailReply, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, outgoing_email_id, from_address, body, created_at
		 FROM email_replies WHERE outgoing_email_id = ? ORDER BY created_at`, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var replies []*model.EmailReply
	for rows.Next() {
		var r model.EmailReply
		var createdAt string
		err := rows.Scan(&r.ID, &r.OutgoingEmailID, &r.FromAddress, &r.Body, &createdAt)
		if err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		replies = append(replies, &r)
	}
	return replies, rows.Err()
}

func (s *SQLiteStore) GetEmailChain(ctx context.Context, emailID string) ([]*model.OutgoingEmail, error) {
	query := `WITH RECURSIVE chain AS (
		SELECT id, parent_email_id FROM outgoing_emails WHERE id = ?
		UNION ALL
		SELECT oe.id, oe.parent_email_id FROM outgoing_emails oe
		JOIN chain c ON c.parent_email_id = oe.id
		WHERE c.parent_email_id != ''
	)
	SELECT id, report_id, parent_email_id, recipient, recipient_org, target_asn, email_type,
	 xarf_json, email_subject, email_body, status, approved_by, approved_at, sent_at,
	 sendgrid_id, escalate_after, response_notes, created_at
	 FROM outgoing_emails WHERE id IN (SELECT id FROM chain)
	 ORDER BY created_at ASC`

	rows, err := s.db.QueryContext(ctx, query, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanEmails(rows)
}

func (s *SQLiteStore) ListAllRepliesByReport(ctx context.Context, reportID string) (map[string][]*model.EmailReply, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT er.id, er.outgoing_email_id, er.from_address, er.body, er.created_at
		 FROM email_replies er
		 JOIN outgoing_emails oe ON er.outgoing_email_id = oe.id
		 WHERE oe.report_id = ?
		 ORDER BY er.created_at`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]*model.EmailReply)
	for rows.Next() {
		var r model.EmailReply
		var createdAt string
		err := rows.Scan(&r.ID, &r.OutgoingEmailID, &r.FromAddress, &r.Body, &createdAt)
		if err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		result[r.OutgoingEmailID] = append(result[r.OutgoingEmailID], &r)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) ListEmailRepliesByEmails(ctx context.Context, emailIDs []string) (map[string][]*model.EmailReply, error) {
	if len(emailIDs) == 0 {
		return make(map[string][]*model.EmailReply), nil
	}

	placeholders := make([]string, len(emailIDs))
	args := make([]interface{}, len(emailIDs))
	for i, id := range emailIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(
		`SELECT id, outgoing_email_id, from_address, body, created_at
		 FROM email_replies WHERE outgoing_email_id IN (%s)
		 ORDER BY created_at`,
		strings.Join(placeholders, ", "))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]*model.EmailReply)
	for rows.Next() {
		var r model.EmailReply
		var createdAt string
		err := rows.Scan(&r.ID, &r.OutgoingEmailID, &r.FromAddress, &r.Body, &createdAt)
		if err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		result[r.OutgoingEmailID] = append(result[r.OutgoingEmailID], &r)
	}
	return result, rows.Err()
}

// --- Upstream Cache ---

func (s *SQLiteStore) UpsertUpstreamCache(ctx context.Context, asn int, upstreams []int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM upstream_cache WHERE asn = ?`, asn); err != nil {
		return fmt.Errorf("delete stale upstreams for AS%d: %w", asn, err)
	}

	for _, upstream := range upstreams {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO upstream_cache (asn, upstream_asn) VALUES (?, ?)`,
			asn, upstream); err != nil {
			return fmt.Errorf("insert upstream AS%d for AS%d: %w", upstream, asn, err)
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetUpstreamsForASN(ctx context.Context, asn int, maxAge time.Duration) ([]int, error) {
	var query string
	var args []interface{}
	if maxAge > 0 {
		query = `SELECT upstream_asn FROM upstream_cache
			WHERE asn = ? AND fetched_at > datetime('now', ?)
			ORDER BY upstream_asn`
		// SQLite datetime modifier: e.g. "-3600 seconds"
		args = []interface{}{asn, fmt.Sprintf("-%d seconds", int(maxAge.Seconds()))}
	} else {
		query = `SELECT upstream_asn FROM upstream_cache
			WHERE asn = ? ORDER BY upstream_asn`
		args = []interface{}{asn}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var upstreams []int
	for rows.Next() {
		var u int
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		upstreams = append(upstreams, u)
	}
	return upstreams, rows.Err()
}

// --- Invites ---

// ErrInviteInvalid is returned when an invite cannot be redeemed
// (expired, revoked, exhausted, or not found).
var ErrInviteInvalid = fmt.Errorf("invite is invalid, expired, revoked, or fully used")

func (s *SQLiteStore) scanInvite(row interface{ Scan(...interface{}) error }) (*model.Invite, error) {
	var inv model.Invite
	var revoked int
	var email, usedBy, expiresAt, createdAt sql.NullString
	err := row.Scan(&inv.ID, &inv.Code, &email, &inv.CreatedBy, &usedBy,
		&inv.MaxUses, &inv.UseCount, &revoked, &expiresAt, &createdAt)
	if err != nil {
		return nil, err
	}
	inv.Email = email.String
	inv.UsedBy = usedBy.String
	inv.Revoked = revoked != 0
	if expiresAt.Valid {
		inv.ExpiresAt, _ = time.Parse(timeFormat, expiresAt.String)
	}
	if createdAt.Valid {
		inv.CreatedAt, _ = time.Parse(timeFormat, createdAt.String)
	}
	return &inv, nil
}

func (s *SQLiteStore) CreateInvite(ctx context.Context, invite *model.Invite) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invites (id, code, email, created_by, used_by, max_uses, use_count, revoked, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invite.ID, invite.Code, nullString(invite.Email), invite.CreatedBy,
		nullString(invite.UsedBy), invite.MaxUses, invite.UseCount,
		boolToInt(invite.Revoked), nullTimeVal(invite.ExpiresAt),
		invite.CreatedAt.UTC().Format(timeFormat))
	return err
}

func (s *SQLiteStore) GetInviteByCode(ctx context.Context, code string) (*model.Invite, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, code, email, created_by, used_by, max_uses, use_count, revoked, expires_at, created_at
		 FROM invites WHERE code = ?`, code)
	return s.scanInvite(row)
}

func (s *SQLiteStore) RedeemInvite(ctx context.Context, code string, userID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE invites SET use_count = use_count + 1, used_by = ?
		 WHERE code = ? AND use_count < max_uses AND revoked = 0
		 AND (expires_at IS NULL OR expires_at = '' OR expires_at > datetime('now'))`,
		userID, code)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInviteInvalid
	}
	return nil
}

func (s *SQLiteStore) ListInvites(ctx context.Context) ([]*model.Invite, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, code, email, created_by, used_by, max_uses, use_count, revoked, expires_at, created_at
		 FROM invites ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []*model.Invite
	for rows.Next() {
		inv, err := s.scanInvite(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, inv)
	}
	return invites, rows.Err()
}

func (s *SQLiteStore) RevokeInvite(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE invites SET revoked = 1 WHERE id = ?`, id)
	return err
}

// --- Helpers ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.UTC().Format(timeFormat), Valid: true}
}

func parseNullTime(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t, _ := time.Parse(timeFormat, s.String)
	return &t
}
