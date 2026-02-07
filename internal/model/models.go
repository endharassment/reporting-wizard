package model

import "time"

// ViolationType represents the kind of abuse being reported.
type ViolationType string

const (
	ViolationHarassment ViolationType = "harassment"
	ViolationHateSpeech ViolationType = "hate_speech"
	ViolationNCII       ViolationType = "ncii"
	ViolationDoxxing    ViolationType = "doxxing"
	ViolationCopyvio    ViolationType = "copyvio"
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
	ID        string
	Email     string
	Name      string
	IsAdmin   bool
	CreatedAt time.Time
}

// Session represents an authenticated session.
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// MagicLink represents a passwordless login token.
type MagicLink struct {
	Token     string
	Email     string
	ExpiresAt time.Time
	Used      bool
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

// Evidence represents an uploaded evidence file.
type Evidence struct {
	ID          string
	ReportID    string
	Filename    string
	ContentType string
	StoragePath string
	SHA256      string
	SizeBytes   int64
	Description string
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
