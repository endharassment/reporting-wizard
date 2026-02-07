package store

import (
	"context"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
)

// Store defines the persistence interface for the reporting wizard.
type Store interface {
	// Users
	CreateUser(ctx context.Context, user *model.User) error
	GetUser(ctx context.Context, id string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	UpdateUser(ctx context.Context, user *model.User) error
	ListUsers(ctx context.Context) ([]*model.User, error)
	BanUser(ctx context.Context, id string) error

	// Sessions
	CreateSession(ctx context.Context, session *model.Session) error
	GetSession(ctx context.Context, id string) (*model.Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error

	// Reports
	CreateReport(ctx context.Context, report *model.Report) error
	GetReport(ctx context.Context, id string) (*model.Report, error)
	UpdateReport(ctx context.Context, report *model.Report) error
	ListReportsByUser(ctx context.Context, userID string) ([]*model.Report, error)
	ListReportsByStatus(ctx context.Context, status model.ReportStatus) ([]*model.Report, error)

	// Infrastructure Results
	CreateInfraResult(ctx context.Context, result *model.InfraResult) error
	ListInfraResultsByReport(ctx context.Context, reportID string) ([]*model.InfraResult, error)
	DeleteInfraResultsByReport(ctx context.Context, reportID string) error

	// Evidence
	CreateEvidence(ctx context.Context, evidence *model.Evidence) error
	UpdateEvidence(ctx context.Context, evidence *model.Evidence) error
	GetEvidence(ctx context.Context, id string) (*model.Evidence, error)
	ListEvidenceByReport(ctx context.Context, reportID string) ([]*model.Evidence, error)

	// URL Snapshots
	CreateURLSnapshot(ctx context.Context, snapshot *model.URLSnapshot) error
	ListURLSnapshotsByReport(ctx context.Context, reportID string) ([]*model.URLSnapshot, error)

	// Outgoing Emails
	CreateOutgoingEmail(ctx context.Context, email *model.OutgoingEmail) error
	GetOutgoingEmail(ctx context.Context, id string) (*model.OutgoingEmail, error)
	UpdateOutgoingEmail(ctx context.Context, email *model.OutgoingEmail) error
	ListEmailsByReport(ctx context.Context, reportID string) ([]*model.OutgoingEmail, error)
	ListEmailsByStatus(ctx context.Context, status model.EmailStatus) ([]*model.OutgoingEmail, error)
	ListEmailsDueForEscalation(ctx context.Context, now time.Time) ([]*model.OutgoingEmail, error)

	// Audit Log
	CreateAuditLogEntry(ctx context.Context, entry *model.AuditLogEntry) error
	ListAuditLogByTarget(ctx context.Context, targetID string) ([]*model.AuditLogEntry, error)

	// Email Replies
	CreateEmailReply(ctx context.Context, reply *model.EmailReply) error
	ListEmailRepliesByEmail(ctx context.Context, emailID string) ([]*model.EmailReply, error)
	GetEmailChain(ctx context.Context, emailID string) ([]*model.OutgoingEmail, error)
	ListAllRepliesByReport(ctx context.Context, reportID string) (map[string][]*model.EmailReply, error)
	ListEmailRepliesByEmails(ctx context.Context, emailIDs []string) (map[string][]*model.EmailReply, error)

	// Upstream Cache (recursive BGP upstream chain)
	UpsertUpstreamCache(ctx context.Context, asn int, upstreams []int) error
	GetUpstreamsForASN(ctx context.Context, asn int) ([]int, error)
}
