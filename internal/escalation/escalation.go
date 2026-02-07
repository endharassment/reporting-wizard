package escalation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/endharassment/reporting-wizard/internal/store"
	"github.com/google/uuid"
)

// AbuseContactLookup resolves an abuse contact email for a given ASN.
type AbuseContactLookup interface {
	LookupAbuseContactByASN(ctx context.Context, asn int) (string, error)
}

// Engine checks for emails that are due for escalation and creates
// escalation emails to upstream providers.
type Engine struct {
	store          store.Store
	abuseContact   AbuseContactLookup
	escalationDays int
	tickInterval   time.Duration
	logger         *slog.Logger
}

// NewEngine creates an escalation engine.
func NewEngine(s store.Store, ac AbuseContactLookup, escalationDays int, logger *slog.Logger) *Engine {
	return &Engine{
		store:          s,
		abuseContact:   ac,
		escalationDays: escalationDays,
		tickInterval:   1 * time.Hour,
		logger:         logger,
	}
}

// SetTickInterval overrides the default tick interval (for testing).
func (e *Engine) SetTickInterval(d time.Duration) {
	e.tickInterval = d
}

// Run starts a ticker loop that calls checkAndEscalate on each tick.
// It blocks until the context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	ticker := time.NewTicker(e.tickInterval)
	defer ticker.Stop()

	// Run once immediately on start.
	e.checkAndEscalate(ctx)

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("escalation engine shutting down")
			return ctx.Err()
		case <-ticker.C:
			e.checkAndEscalate(ctx)
		}
	}
}

// checkAndEscalate finds emails due for escalation and creates escalation
// emails to upstream providers.
func (e *Engine) checkAndEscalate(ctx context.Context) {
	now := time.Now().UTC()

	dueEmails, err := e.store.ListEmailsDueForEscalation(ctx, now)
	if err != nil {
		e.logger.Error("listing emails due for escalation", "error", err)
		return
	}

	escalationsCreated := 0

	for _, email := range dueEmails {
		if email.ResponseNotes != "" {
			continue
		}

		created, err := e.escalateEmail(ctx, email, now)
		if err != nil {
			e.logger.Error("escalating email",
				"email_id", email.ID,
				"report_id", email.ReportID,
				"error", err,
			)
			continue
		}
		escalationsCreated += created
	}

	e.logger.Info("escalation check complete",
		"emails_checked", len(dueEmails),
		"escalations_created", escalationsCreated,
	)
}

// escalateEmail processes a single email due for escalation.
// It returns the number of escalation emails created.
func (e *Engine) escalateEmail(ctx context.Context, email *model.OutgoingEmail, now time.Time) (int, error) {
	report, err := e.store.GetReport(ctx, email.ReportID)
	if err != nil {
		return 0, fmt.Errorf("getting report %s: %w", email.ReportID, err)
	}

	infraResults, err := e.store.ListInfraResultsByReport(ctx, email.ReportID)
	if err != nil {
		return 0, fmt.Errorf("listing infra results for report %s: %w", email.ReportID, err)
	}

	// Collect unique upstream ASNs across all infra results.
	upstreamASNs := make(map[int]bool)
	for _, ir := range infraResults {
		for _, asn := range ir.UpstreamASNs {
			upstreamASNs[asn] = true
		}
	}

	if len(upstreamASNs) == 0 {
		e.logger.Warn("no upstream ASNs found for escalation",
			"email_id", email.ID,
			"report_id", email.ReportID,
		)
	}

	created := 0
	// Deduplicate abuse contacts to avoid sending multiple emails to the same address.
	seenContacts := make(map[string]bool)

	for asn := range upstreamASNs {
		abuseContact, err := e.abuseContact.LookupAbuseContactByASN(ctx, asn)
		if err != nil {
			e.logger.Error("looking up abuse contact for upstream ASN",
				"asn", asn,
				"email_id", email.ID,
				"error", err,
			)
			continue
		}
		if abuseContact == "" {
			e.logger.Warn("no abuse contact found for upstream ASN",
				"asn", asn,
				"email_id", email.ID,
			)
			continue
		}

		if seenContacts[abuseContact] {
			continue
		}
		seenContacts[abuseContact] = true

		sentDate := ""
		if email.SentAt != nil {
			sentDate = email.SentAt.Format("2006-01-02")
		} else {
			sentDate = email.CreatedAt.Format("2006-01-02")
		}

		days := int(now.Sub(email.CreatedAt).Hours() / 24)

		body := composeEscalationBody(report, email, asn, sentDate, days)
		subject := fmt.Sprintf("Escalation: Abuse Report for %s (upstream AS%d)", report.Domain, asn)

		escAfter := now.Add(time.Duration(e.escalationDays) * 24 * time.Hour)

		escEmail := &model.OutgoingEmail{
			ID:            uuid.New().String(),
			ReportID:      email.ReportID,
			ParentEmailID: email.ID,
			Recipient:     abuseContact,
			RecipientOrg:  fmt.Sprintf("AS%d", asn),
			TargetASN:     asn,
			EmailType:     model.EmailTypeEscalation,
			XARFJson:      email.XARFJson,
			EmailSubject:  subject,
			EmailBody:     body,
			Status:        model.EmailPendingApproval,
			EscalateAfter: &escAfter,
			CreatedAt:     now,
		}

		if err := e.store.CreateOutgoingEmail(ctx, escEmail); err != nil {
			e.logger.Error("creating escalation email",
				"upstream_asn", asn,
				"email_id", email.ID,
				"error", err,
			)
			continue
		}

		e.logger.Info("created escalation email",
			"escalation_id", escEmail.ID,
			"upstream_asn", asn,
			"recipient", abuseContact,
			"parent_email_id", email.ID,
		)
		created++
	}

	// Mark the original email so it is not picked up again.
	email.ResponseNotes = "escalated"
	if err := e.store.UpdateOutgoingEmail(ctx, email); err != nil {
		return created, fmt.Errorf("updating response_notes for email %s: %w", email.ID, err)
	}

	return created, nil
}

func composeEscalationBody(report *model.Report, original *model.OutgoingEmail, upstreamASN int, sentDate string, days int) string {
	var b strings.Builder

	b.WriteString("Dear Abuse Team,\n\n")
	b.WriteString(fmt.Sprintf(
		"Report %s regarding %s was filed with %s (AS%d) on %s. "+
			"No action has been taken after %d days. "+
			"We are escalating to you as an upstream provider.\n\n",
		report.ID, report.Domain, original.Recipient, original.TargetASN, sentDate, days,
	))

	b.WriteString("Original report details:\n")
	b.WriteString(fmt.Sprintf("  Domain: %s\n", report.Domain))
	if len(report.URLs) > 0 {
		b.WriteString("  URLs:\n")
		for _, u := range report.URLs {
			b.WriteString(fmt.Sprintf("    - %s\n", u))
		}
	}
	b.WriteString(fmt.Sprintf("  Violation: %s\n", report.ViolationType))
	b.WriteString(fmt.Sprintf("  Description: %s\n\n", report.Description))

	b.WriteString("The original machine-readable X-ARF v4 report is attached to this email.\n\n")
	b.WriteString("We request that you investigate this matter and take appropriate action.\n\n")
	b.WriteString("Regards,\n")
	b.WriteString("End Harassment Reporting Wizard\n")

	return b.String()
}
