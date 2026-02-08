package model

import "time"

// ViolationType represents the kind of abuse being reported.
type ViolationType string

const (
	ViolationHarassment       ViolationType = "harassment"
	ViolationHateSpeech       ViolationType = "hate_speech"
	ViolationNCII             ViolationType = "ncii"
	ViolationDoxxing          ViolationType = "doxxing"
	ViolationCopyvio          ViolationType = "copyvio"
	ViolationSelfHarmFacility ViolationType = "self_harm_facilitation"
	ViolationDefamation       ViolationType = "defamation"
	ViolationThreats          ViolationType = "threats"
)

// ReportStatus tracks a report through its lifecycle.
type ReportStatus string

const (
	StatusDraft            ReportStatus = "draft"
	StatusPendingApproval  ReportStatus = "pending_approval"
	StatusCloudfarePending ReportStatus = "cloudflare_pending"
	StatusSent             ReportStatus = "sent"
	StatusAwaitingResponse ReportStatus = "awaiting_response"
	StatusEscalating       ReportStatus = "escalating"
	StatusResolved         ReportStatus = "resolved"
)

// EmailStatus tracks an outgoing email through its lifecycle.
type EmailStatus string

const (
	EmailPendingApproval EmailStatus = "pending_approval"
	EmailApproved        EmailStatus = "approved"
	EmailSent            EmailStatus = "sent"
	EmailBounced         EmailStatus = "bounced"
	EmailRejected        EmailStatus = "rejected"
)

// EmailType classifies outgoing emails.
type EmailType string

const (
	EmailTypeInitialReport EmailType = "initial_report"
	EmailTypeEscalation    EmailType = "escalation"
	EmailTypeCloudflare    EmailType = "cloudflare"
)

// User represents a reporter or admin.
type User struct {
	ID                 string
	Email              string
	Name               string
	IsAdmin            bool
	Banned             bool
	GoogleAccessToken  string
	GoogleRefreshToken string
	GoogleTokenExpiry  time.Time
	CreatedAt          time.Time
}

// Session represents an authenticated session.
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Report represents an abuse report targeting a single domain.
type Report struct {
	ID                 string
	UserID             string
	Domain             string
	URLs               []string // stored as JSON in DB
	ViolationType      ViolationType
	Description        string
	Status             ReportStatus
	CloudflareOriginIP string // set by admin when Cloudflare reveals origin
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// InfraResult represents discovered infrastructure for a report's domain.
type InfraResult struct {
	ID           string
	ReportID     string
	IP           string
	RecordType   string // "A" or "AAAA"
	ASN          int
	ASNName      string
	BGPPrefix    string
	Country      string
	AbuseContact string
	IsCloudflare bool
	UpstreamASNs []int // stored as JSON in DB
	CreatedAt    time.Time
}

// Evidence represents a piece of evidence for a report. Evidence can be either
// a URL pointing to user-hosted content (e.g., Google Drive, Dropbox) or
// a locally stored file (legacy).
type Evidence struct {
	ID          string
	ReportID    string
	Filename    string // empty for URL-only evidence
	ContentType string // empty for URL-only evidence
	StoragePath string // empty for URL-only evidence
	SHA256      string // empty for URL-only evidence
	SizeBytes   int64  // 0 for URL-only evidence
	EvidenceURL string // URL to cloud-hosted evidence (primary method)
	Description string
	// Google Drive metadata (populated when evidence URL is a Drive link).
	DriveFileID   string
	DriveFileName string
	DriveMimeType string
	DriveSize     int64
	DriveVerified bool
	CreatedAt     time.Time
}

// URLSnapshot represents a text-only crawl of a reported URL.
type URLSnapshot struct {
	ID          string
	ReportID    string
	URL         string
	TextContent string
	FetchedAt   time.Time
	Error       string
	CreatedAt   time.Time
}

// OutgoingEmail represents an email queued for sending.
type OutgoingEmail struct {
	ID            string
	ReportID      string
	ParentEmailID string // links to prior report in escalation chain
	Recipient     string
	RecipientOrg  string
	TargetASN     int
	EmailType     EmailType
	XARFJson      string
	EmailSubject  string
	EmailBody     string
	Status        EmailStatus
	ApprovedBy    string
	ApprovedAt    *time.Time
	SentAt        *time.Time
	SendGridID    string
	EscalateAfter *time.Time
	ResponseNotes string
	CreatedAt     time.Time
}

// AuditLogEntry records an admin action.
type AuditLogEntry struct {
	ID        string
	UserID    string
	Action    string
	TargetID  string
	Details   string
	CreatedAt time.Time
}

// EmailReply represents a reply to an outgoing email.
type EmailReply struct {
	ID              string
	OutgoingEmailID string
	FromAddress     string
	Body            string
	CreatedAt       time.Time
}
