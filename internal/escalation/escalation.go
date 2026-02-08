package escalation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/boilerplate"
	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/endharassment/reporting-wizard/internal/store"
	"github.com/google/uuid"
)

// AbuseContactLookup resolves an abuse contact email for a given ASN.
type AbuseContactLookup interface {
	LookupAbuseContactByASN(ctx context.Context, asn int) (string, error)
}

// upstreamTarget holds a resolved upstream ASN and its abuse contact.
type upstreamTarget struct {
	ASN          int
	AbuseContact string
}

// Engine checks for emails that are due for escalation and creates
// escalation emails to upstream providers.
type Engine struct {
	store          store.Store
	abuseContact   AbuseContactLookup
	boilerplate    *boilerplate.DB
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

// SetBoilerplate configures the domain boilerplate database.
func (e *Engine) SetBoilerplate(db *boilerplate.DB) {
	e.boilerplate = db
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

// EscalateNow immediately triggers escalation for a specific email,
// bypassing the escalation timer. This is used when an admin sees a
// provider refusal and wants to escalate right away.
func (e *Engine) EscalateNow(ctx context.Context, emailID string) (int, error) {
	email, err := e.store.GetOutgoingEmail(ctx, emailID)
	if err != nil {
		return 0, fmt.Errorf("getting email %s: %w", emailID, err)
	}

	// Clear ResponseNotes so the email is eligible for escalation.
	email.ResponseNotes = ""
	if err := e.store.UpdateOutgoingEmail(ctx, email); err != nil {
		return 0, fmt.Errorf("clearing response_notes for email %s: %w", emailID, err)
	}

	return e.escalateEmail(ctx, email, time.Now().UTC())
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
// It looks up the TARGET ASN's upstreams from the upstream cache (not the
// report's infra_results), so escalation works recursively: an escalation
// email to AS56655 that times out will escalate to AS56655's upstreams.
//
// Each downstream's failure to act is a separate complaint — no cross-round
// deduplication. If AS56655 and AS1002 both ignore us and both have AS174
// as upstream, AS174 gets two escalation emails (one per downstream).
func (e *Engine) escalateEmail(ctx context.Context, email *model.OutgoingEmail, now time.Time) (int, error) {
	report, err := e.store.GetReport(ctx, email.ReportID)
	if err != nil {
		return 0, fmt.Errorf("getting report %s: %w", email.ReportID, err)
	}

	if email.TargetASN == 0 {
		e.logger.Warn("email has no target ASN, cannot escalate",
			"email_id", email.ID,
			"report_id", email.ReportID,
		)
		email.ResponseNotes = "escalated"
		if err := e.store.UpdateOutgoingEmail(ctx, email); err != nil {
			return 0, fmt.Errorf("updating response_notes for email %s: %w", email.ID, err)
		}
		return 0, nil
	}

	// Get the full email chain for contact history.
	chain, err := e.store.GetEmailChain(ctx, email.ID)
	if err != nil {
		e.logger.Warn("could not fetch email chain, proceeding without history",
			"email_id", email.ID, "error", err)
		chain = []*model.OutgoingEmail{email}
	}

	// Batch-fetch replies for all emails in the chain.
	chainIDs := make([]string, len(chain))
	for i, ce := range chain {
		chainIDs[i] = ce.ID
	}
	repliesByEmail, err := e.store.ListEmailRepliesByEmails(ctx, chainIDs)
	if err != nil {
		e.logger.Warn("could not fetch chain replies, proceeding without",
			"email_id", email.ID, "error", err)
		repliesByEmail = make(map[string][]*model.EmailReply)
	}

	// Look up domain boilerplate.
	var domainInfo *boilerplate.DomainInfo
	if e.boilerplate != nil {
		domainInfo = e.boilerplate.Lookup(report.Domain)
	}

	// Look up the target ASN's upstreams from the recursive cache.
	// Use 0 maxAge: the escalation engine should use whatever is cached,
	// even if stale, because re-fetching is done during discovery.
	upstreamASNs, err := e.store.GetUpstreamsForASN(ctx, email.TargetASN, 0)
	if err != nil {
		return 0, fmt.Errorf("looking up upstreams for AS%d: %w", email.TargetASN, err)
	}

	if len(upstreamASNs) == 0 {
		e.logger.Info("no upstream ASNs for target (Tier 1 or uncached)",
			"target_asn", email.TargetASN,
			"email_id", email.ID,
			"report_id", email.ReportID,
		)
	}

	// First pass: resolve all upstream contacts so we know the full peer set.
	var targets []upstreamTarget
	seenContacts := make(map[string]bool)

	for _, asn := range upstreamASNs {
		abuseContact, err := e.abuseContact.LookupAbuseContactByASN(ctx, asn)
		if err != nil {
			e.logger.Error("looking up abuse contact for upstream ASN",
				"asn", asn, "email_id", email.ID, "error", err)
			continue
		}
		if abuseContact == "" {
			e.logger.Warn("no abuse contact found for upstream ASN",
				"asn", asn, "email_id", email.ID)
			continue
		}
		if seenContacts[abuseContact] {
			continue
		}
		seenContacts[abuseContact] = true
		targets = append(targets, upstreamTarget{ASN: asn, AbuseContact: abuseContact})
	}

	// Second pass: create escalation emails with full context.
	created := 0
	for _, target := range targets {
		// Build peer list (all other targets in this batch).
		var peers []upstreamTarget
		for _, other := range targets {
			if other.ASN != target.ASN {
				peers = append(peers, other)
			}
		}

		body := composeEscalationBody(report, chain, repliesByEmail, target.ASN, peers, domainInfo, now)
		subject := fmt.Sprintf("Escalation: Abuse Report for %s (upstream AS%d)", report.Domain, target.ASN)

		escAfter := now.Add(time.Duration(e.escalationDays) * 24 * time.Hour)

		escEmail := &model.OutgoingEmail{
			ID:            uuid.New().String(),
			ReportID:      email.ReportID,
			ParentEmailID: email.ID,
			Recipient:     target.AbuseContact,
			RecipientOrg:  fmt.Sprintf("AS%d", target.ASN),
			TargetASN:     target.ASN,
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
				"upstream_asn", target.ASN,
				"email_id", email.ID,
				"error", err,
			)
			continue
		}

		e.logger.Info("created escalation email",
			"escalation_id", escEmail.ID,
			"upstream_asn", target.ASN,
			"recipient", target.AbuseContact,
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

func composeEscalationBody(
	report *model.Report,
	chain []*model.OutgoingEmail,
	repliesByEmail map[string][]*model.EmailReply,
	targetASN int,
	peers []upstreamTarget,
	domainInfo *boilerplate.DomainInfo,
	now time.Time,
) string {
	var b strings.Builder

	b.WriteString("Dear Abuse Team,\n\n")

	// Identify the downstream provider (first email in the chain, the initial report).
	if len(chain) > 0 {
		initial := chain[0]
		b.WriteString(fmt.Sprintf(
			"We are escalating an abuse report regarding %s to you as an upstream "+
				"provider of %s (AS%d).\n\n",
			report.Domain, initial.RecipientOrg, initial.TargetASN,
		))
	}

	// Contact History section.
	if len(chain) > 0 {
		b.WriteString("== Contact History ==\n\n")
		for i, ce := range chain {
			sentDate := "not yet sent"
			if ce.SentAt != nil {
				sentDate = ce.SentAt.Format("2006-01-02")
			}

			label := "Initial report"
			if ce.EmailType == model.EmailTypeEscalation {
				label = "Escalation"
			}

			b.WriteString(fmt.Sprintf("%d. %s to %s (%s)\n",
				i+1, label, ce.Recipient, ce.RecipientOrg))
			b.WriteString(fmt.Sprintf("   Sent: %s\n", sentDate))

			// Show replies for this email.
			replies := repliesByEmail[ce.ID]
			if len(replies) > 0 {
				for _, r := range replies {
					b.WriteString(fmt.Sprintf("   Reply from %s on %s:\n",
						r.FromAddress, r.CreatedAt.Format("2006-01-02")))
					// Truncate reply body to 500 chars for the escalation email.
					body := r.Body
					if len(body) > 500 {
						body = body[:500] + "..."
					}
					// Indent each line of the reply.
					for _, line := range strings.Split(body, "\n") {
						b.WriteString(fmt.Sprintf("     %s\n", line))
					}
				}
			}

			// Show status.
			if ce.ResponseNotes == "escalated" {
				if ce.SentAt != nil {
					days := int(now.Sub(*ce.SentAt).Hours() / 24)
					b.WriteString(fmt.Sprintf("   Status: No action taken after %d days\n", days))
				} else {
					b.WriteString("   Status: Escalated\n")
				}
			} else if ce.ResponseNotes != "" && len(replies) == 0 {
				b.WriteString(fmt.Sprintf("   Status: %s\n", ce.ResponseNotes))
			} else if len(replies) > 0 {
				b.WriteString("   Status: Reply received, no resolution\n")
			} else {
				b.WriteString("   Status: No response\n")
			}
			b.WriteString("\n")
		}

		b.WriteString(fmt.Sprintf("%d. Current escalation to you (AS%d)\n\n",
			len(chain)+1, targetASN))
	}

	// Domain boilerplate section.
	if domainInfo != nil {
		b.WriteString(fmt.Sprintf("== Context regarding %s ==\n\n", domainInfo.DisplayName))
		b.WriteString(domainInfo.Summary)
		b.WriteString("\n\n")
		b.WriteString(domainInfo.Context)
		b.WriteString("\n\n")
	}

	// Peer escalations section.
	if len(peers) > 0 {
		b.WriteString("== Peer Escalations ==\n\n")
		b.WriteString("This report is also being escalated to:\n")
		for _, peer := range peers {
			b.WriteString(fmt.Sprintf("  - %s (AS%d)\n", peer.AbuseContact, peer.ASN))
		}
		b.WriteString("\n")
	}

	// Original report details.
	b.WriteString("== Original Report Details ==\n\n")
	b.WriteString(fmt.Sprintf("Domain: %s\n", report.Domain))
	if len(report.URLs) > 0 {
		b.WriteString("URLs:\n")
		for _, u := range report.URLs {
			b.WriteString(fmt.Sprintf("  - %s\n", u))
		}
	}
	b.WriteString(fmt.Sprintf("Violation: %s\n", report.ViolationType))
	b.WriteString(fmt.Sprintf("Description: %s\n\n", report.Description))

	b.WriteString("A machine-readable X-ARF v4 report is attached to this email.\n\n")
	b.WriteString("We request that you investigate this matter and take appropriate action.\n\n")
	b.WriteString("Regards,\n")
	b.WriteString("End Network Harassment Inc Reporting Wizard\n")

	return b.String()
}
