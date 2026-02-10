package escalation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endharassment/reporting-wizard/internal/boilerplate"
	"github.com/endharassment/reporting-wizard/internal/model"
)

// mockStore implements store.Store with in-memory maps. Only the methods
// needed by the escalation engine are fully implemented; all others panic.
type mockStore struct {
	mu             sync.Mutex
	reports        map[string]*model.Report
	infraResults   map[string][]*model.InfraResult // keyed by report ID
	outgoingEmails map[string]*model.OutgoingEmail
	emailReplies   map[string][]*model.EmailReply // keyed by outgoing email ID
	dueEmails      []*model.OutgoingEmail
	upstreamCache  map[int][]int // ASN -> upstream ASNs
}

func newMockStore() *mockStore {
	return &mockStore{
		reports:        make(map[string]*model.Report),
		infraResults:   make(map[string][]*model.InfraResult),
		outgoingEmails: make(map[string]*model.OutgoingEmail),
		emailReplies:   make(map[string][]*model.EmailReply),
		upstreamCache:  make(map[int][]int),
	}
}

func (m *mockStore) ListEmailsDueForEscalation(_ context.Context, _ time.Time) ([]*model.OutgoingEmail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dueEmails, nil
}

func (m *mockStore) GetReport(_ context.Context, id string) (*model.Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reports[id]
	if !ok {
		return nil, fmt.Errorf("report %s not found", id)
	}
	return r, nil
}

func (m *mockStore) ListInfraResultsByReport(_ context.Context, reportID string) ([]*model.InfraResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.infraResults[reportID], nil
}

func (m *mockStore) CreateOutgoingEmail(_ context.Context, email *model.OutgoingEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outgoingEmails[email.ID] = email
	return nil
}

func (m *mockStore) UpdateOutgoingEmail(_ context.Context, email *model.OutgoingEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outgoingEmails[email.ID] = email
	return nil
}

func (m *mockStore) GetOutgoingEmail(_ context.Context, id string) (*model.OutgoingEmail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.outgoingEmails[id]
	if !ok {
		return nil, fmt.Errorf("email %s not found", id)
	}
	return e, nil
}

func (m *mockStore) GetEmailChain(_ context.Context, emailID string) ([]*model.OutgoingEmail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Walk the parent chain to build the full chain.
	var chain []*model.OutgoingEmail
	current, ok := m.outgoingEmails[emailID]
	if !ok {
		return nil, fmt.Errorf("email %s not found", emailID)
	}

	// Walk up to root.
	var ids []string
	for current != nil {
		ids = append([]string{current.ID}, ids...)
		if current.ParentEmailID == "" {
			break
		}
		parent, ok := m.outgoingEmails[current.ParentEmailID]
		if !ok {
			break
		}
		current = parent
	}

	for _, id := range ids {
		if e, ok := m.outgoingEmails[id]; ok {
			chain = append(chain, e)
		}
	}
	return chain, nil
}

func (m *mockStore) ListEmailRepliesByEmails(_ context.Context, emailIDs []string) (map[string][]*model.EmailReply, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string][]*model.EmailReply)
	for _, id := range emailIDs {
		if replies, ok := m.emailReplies[id]; ok {
			result[id] = replies
		}
	}
	return result, nil
}

func (m *mockStore) ListEmailsByReport(_ context.Context, reportID string) ([]*model.OutgoingEmail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*model.OutgoingEmail
	for _, e := range m.outgoingEmails {
		if e.ReportID == reportID {
			result = append(result, e)
		}
	}
	return result, nil
}

// createdEscalations returns escalation emails created during the test
// (status pending_approval), excluding pre-existing due emails (status sent).
func (m *mockStore) createdEscalations() []*model.OutgoingEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*model.OutgoingEmail
	for _, e := range m.outgoingEmails {
		if e.EmailType == model.EmailTypeEscalation && e.Status == model.EmailPendingApproval {
			result = append(result, e)
		}
	}
	return result
}

// Unused store.Store methods — panic if called unexpectedly.
func (m *mockStore) CreateUser(context.Context, *model.User) error        { panic("not implemented") }
func (m *mockStore) GetUser(context.Context, string) (*model.User, error) { panic("not implemented") }
func (m *mockStore) GetUserByEmail(context.Context, string) (*model.User, error) {
	panic("not implemented")
}
func (m *mockStore) UpdateUser(context.Context, *model.User) error       { panic("not implemented") }
func (m *mockStore) ListUsers(context.Context) ([]*model.User, error)    { panic("not implemented") }
func (m *mockStore) BanUser(context.Context, string) error               { panic("not implemented") }
func (m *mockStore) CreateSession(context.Context, *model.Session) error { panic("not implemented") }
func (m *mockStore) GetSession(context.Context, string) (*model.Session, error) {
	panic("not implemented")
}
func (m *mockStore) DeleteSession(context.Context, string) error { panic("not implemented") }
func (m *mockStore) DeleteExpiredSessions(context.Context) error { panic("not implemented") }
func (m *mockStore) CreateReport(context.Context, *model.Report) error {
	panic("not implemented")
}
func (m *mockStore) UpdateReport(context.Context, *model.Report) error {
	panic("not implemented")
}
func (m *mockStore) ListReportsByUser(context.Context, string) ([]*model.Report, error) {
	panic("not implemented")
}
func (m *mockStore) ListReportsByStatus(context.Context, model.ReportStatus) ([]*model.Report, error) {
	panic("not implemented")
}
func (m *mockStore) CreateInfraResult(context.Context, *model.InfraResult) error {
	panic("not implemented")
}
func (m *mockStore) DeleteInfraResultsByReport(context.Context, string) error {
	panic("not implemented")
}
func (m *mockStore) CreateEvidence(context.Context, *model.Evidence) error {
	panic("not implemented")
}
func (m *mockStore) UpdateEvidence(context.Context, *model.Evidence) error {
	panic("not implemented")
}
func (m *mockStore) GetEvidence(context.Context, string) (*model.Evidence, error) {
	panic("not implemented")
}
func (m *mockStore) ListEvidenceByReport(context.Context, string) ([]*model.Evidence, error) {
	panic("not implemented")
}
func (m *mockStore) ListEmailsByStatus(context.Context, model.EmailStatus) ([]*model.OutgoingEmail, error) {
	panic("not implemented")
}
func (m *mockStore) CreateAuditLogEntry(context.Context, *model.AuditLogEntry) error {
	panic("not implemented")
}
func (m *mockStore) ListAuditLogByTarget(context.Context, string) ([]*model.AuditLogEntry, error) {
	panic("not implemented")
}
func (m *mockStore) CreateURLSnapshot(context.Context, *model.URLSnapshot) error {
	panic("not implemented")
}
func (m *mockStore) ListURLSnapshotsByReport(context.Context, string) ([]*model.URLSnapshot, error) {
	panic("not implemented")
}
func (m *mockStore) CreateEmailReply(context.Context, *model.EmailReply) error {
	panic("not implemented")
}
func (m *mockStore) ListEmailRepliesByEmail(context.Context, string) ([]*model.EmailReply, error) {
	panic("not implemented")
}
func (m *mockStore) ListAllRepliesByReport(context.Context, string) (map[string][]*model.EmailReply, error) {
	panic("not implemented")
}

func (m *mockStore) UpsertUpstreamCache(_ context.Context, asn int, upstreams []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamCache[asn] = upstreams
	return nil
}

func (m *mockStore) GetUpstreamsForASN(_ context.Context, asn int, _ time.Duration) ([]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamCache[asn], nil
}

func (m *mockStore) CreateInvite(_ context.Context, _ *model.Invite) error { return nil }
func (m *mockStore) GetInviteByCode(_ context.Context, _ string) (*model.Invite, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockStore) RedeemInvite(_ context.Context, _ string, _ string) error { return nil }
func (m *mockStore) ListInvites(_ context.Context) ([]*model.Invite, error)   { return nil, nil }
func (m *mockStore) RevokeInvite(_ context.Context, _ string) error           { return nil }

// mockAbuseContactLookup maps ASN -> abuse contact email.
type mockAbuseContactLookup struct {
	contacts map[int]string
}

func (m *mockAbuseContactLookup) LookupAbuseContactByASN(_ context.Context, asn int) (string, error) {
	contact, ok := m.contacts[asn]
	if !ok {
		return "", fmt.Errorf("no abuse contact for ASN %d", asn)
	}
	return contact, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestCheckAndEscalate(t *testing.T) {
	now := time.Now().UTC()
	pastDate := now.Add(-10 * 24 * time.Hour)
	sentAt := pastDate
	_ = now.Add(10 * 24 * time.Hour) // futureDate unused; store filters by time

	tests := []struct {
		name                string
		dueEmails           []*model.OutgoingEmail
		reports             map[string]*model.Report
		upstreamCache       map[int][]int // ASN -> upstream ASNs
		abuseContacts       map[int]string
		wantEscalationCount int
		wantOriginalNotes   string // expected ResponseNotes on the original email
	}{
		{
			name: "email due for escalation creates escalation emails to upstream contacts",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "email-1",
					ReportID:      "report-1",
					Recipient:     "abuse@hosting.example.com",
					RecipientOrg:  "HOSTING-EXAMPLE",
					TargetASN:     65001,
					EmailType:     model.EmailTypeInitialReport,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					CreatedAt:     pastDate,
				},
			},
			reports: map[string]*model.Report{
				"report-1": {
					ID:            "report-1",
					Domain:        "bad.example.com",
					URLs:          []string{"https://bad.example.com/page1"},
					ViolationType: model.ViolationHarassment,
					Description:   "Harassment content",
				},
			},
			upstreamCache: map[int][]int{
				65001: {174, 3356},
			},
			abuseContacts: map[int]string{
				174:  "abuse@cogent.net",
				3356: "abuse@lumen.com",
			},
			wantEscalationCount: 2,
			wantOriginalNotes:   "escalated",
		},
		{
			name:                "email not yet due is not returned by store",
			dueEmails:           []*model.OutgoingEmail{},
			reports:             map[string]*model.Report{},
			upstreamCache:       map[int][]int{},
			abuseContacts:       map[int]string{},
			wantEscalationCount: 0,
		},
		{
			name: "email with response_notes set is skipped",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "email-2",
					ReportID:      "report-2",
					Recipient:     "abuse@hosting.example.com",
					RecipientOrg:  "HOSTING-EXAMPLE",
					TargetASN:     65001,
					EmailType:     model.EmailTypeInitialReport,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					ResponseNotes: "already handled",
					CreatedAt:     pastDate,
				},
			},
			reports: map[string]*model.Report{
				"report-2": {
					ID:     "report-2",
					Domain: "bad.example.com",
				},
			},
			upstreamCache:       map[int][]int{},
			abuseContacts:       map[int]string{},
			wantEscalationCount: 0,
		},
		{
			name: "multiple upstream ASNs creates one escalation per unique abuse contact",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "email-3",
					ReportID:      "report-3",
					Recipient:     "abuse@hosting.example.com",
					RecipientOrg:  "HOSTING-EXAMPLE",
					TargetASN:     65001,
					EmailType:     model.EmailTypeInitialReport,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					CreatedAt:     pastDate,
				},
			},
			reports: map[string]*model.Report{
				"report-3": {
					ID:            "report-3",
					Domain:        "bad.example.com",
					URLs:          []string{"https://bad.example.com/page1"},
					ViolationType: model.ViolationDoxxing,
					Description:   "Doxxing content",
				},
			},
			upstreamCache: map[int][]int{
				65001: {174, 3356, 6939},
			},
			abuseContacts: map[int]string{
				174:  "abuse@cogent.net",
				3356: "abuse@lumen.com",
				6939: "abuse@he.net",
			},
			wantEscalationCount: 3,
			wantOriginalNotes:   "escalated",
		},
		{
			name: "duplicate abuse contacts across ASNs are deduplicated within round",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "email-4",
					ReportID:      "report-4",
					Recipient:     "abuse@hosting.example.com",
					RecipientOrg:  "HOSTING-EXAMPLE",
					TargetASN:     65001,
					EmailType:     model.EmailTypeInitialReport,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					CreatedAt:     pastDate,
				},
			},
			reports: map[string]*model.Report{
				"report-4": {
					ID:            "report-4",
					Domain:        "bad.example.com",
					URLs:          []string{"https://bad.example.com/page1"},
					ViolationType: model.ViolationHarassment,
					Description:   "Harassment content",
				},
			},
			upstreamCache: map[int][]int{
				65001: {174, 3356},
			},
			abuseContacts: map[int]string{
				// Both ASNs resolve to the same abuse contact
				174:  "abuse@same-parent.net",
				3356: "abuse@same-parent.net",
			},
			wantEscalationCount: 1,
			wantOriginalNotes:   "escalated",
		},
		{
			name: "Tier 1 ASN with no upstreams produces zero escalations",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "email-5",
					ReportID:      "report-5",
					Recipient:     "abuse@cogent.net",
					TargetASN:     174,
					EmailType:     model.EmailTypeEscalation,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					CreatedAt:     pastDate,
				},
			},
			reports: map[string]*model.Report{
				"report-5": {
					ID:     "report-5",
					Domain: "bad.example.com",
				},
			},
			upstreamCache: map[int][]int{
				174: {}, // Tier 1 — no upstreams
			},
			abuseContacts:       map[int]string{},
			wantEscalationCount: 0,
			wantOriginalNotes:   "escalated",
		},
		{
			name:                "escalate_after in future is unused because store already filters",
			dueEmails:           []*model.OutgoingEmail{},
			reports:             map[string]*model.Report{},
			upstreamCache:       map[int][]int{},
			abuseContacts:       map[int]string{},
			wantEscalationCount: 0,
		},
		{
			name: "recursive: escalation email to AS56655 escalates to AS56655 upstreams",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "esc-56655",
					ReportID:      "report-6",
					ParentEmailID: "initial-email",
					Recipient:     "abuse@56655.example.com",
					TargetASN:     56655,
					EmailType:     model.EmailTypeEscalation,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					CreatedAt:     pastDate,
				},
			},
			reports: map[string]*model.Report{
				"report-6": {
					ID:            "report-6",
					Domain:        "kiwifarms.example.com",
					URLs:          []string{"https://kiwifarms.example.com/page"},
					ViolationType: model.ViolationHarassment,
					Description:   "Harassment content",
				},
			},
			upstreamCache: map[int][]int{
				56655: {174, 3356},
				174:   {}, // Tier 1
				3356:  {}, // Tier 1
			},
			abuseContacts: map[int]string{
				174:  "abuse@cogent.net",
				3356: "abuse@lumen.com",
			},
			wantEscalationCount: 2,
			wantOriginalNotes:   "escalated",
		},
		{
			name: "no cross-round dedup: two downstreams sharing upstream each produce escalation",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "esc-56655-r7",
					ReportID:      "report-7",
					ParentEmailID: "initial-email-r7",
					Recipient:     "abuse@56655.example.com",
					TargetASN:     56655,
					EmailType:     model.EmailTypeEscalation,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					CreatedAt:     pastDate,
				},
				{
					ID:            "esc-1002-r7",
					ReportID:      "report-7",
					ParentEmailID: "initial-email-r7",
					Recipient:     "abuse@1002.example.com",
					TargetASN:     1002,
					EmailType:     model.EmailTypeEscalation,
					Status:        model.EmailSent,
					SentAt:        &sentAt,
					EscalateAfter: &pastDate,
					CreatedAt:     pastDate,
				},
			},
			reports: map[string]*model.Report{
				"report-7": {
					ID:            "report-7",
					Domain:        "kiwifarms.example.com",
					URLs:          []string{"https://kiwifarms.example.com/page"},
					ViolationType: model.ViolationHarassment,
					Description:   "Harassment content",
				},
			},
			upstreamCache: map[int][]int{
				56655: {174},
				1002:  {174},
				174:   {}, // Tier 1
			},
			abuseContacts: map[int]string{
				174: "abuse@cogent.net",
			},
			// Both AS56655 and AS1002 escalate to AS174 independently.
			// No dedup: AS174 gets 2 separate escalation emails.
			wantEscalationCount: 2,
			wantOriginalNotes:   "escalated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMockStore()
			s.dueEmails = tt.dueEmails
			s.reports = tt.reports
			s.upstreamCache = tt.upstreamCache

			// Also store the due emails so UpdateOutgoingEmail works.
			for _, e := range tt.dueEmails {
				s.outgoingEmails[e.ID] = e
			}

			ac := &mockAbuseContactLookup{contacts: tt.abuseContacts}
			engine := NewEngine(s, ac, 7, testLogger())

			engine.checkAndEscalate(context.Background())

			escalations := s.createdEscalations()
			if len(escalations) != tt.wantEscalationCount {
				t.Errorf("got %d escalation emails, want %d", len(escalations), tt.wantEscalationCount)
			}

			// Verify escalation email properties.
			for _, esc := range escalations {
				if esc.EmailType != model.EmailTypeEscalation {
					t.Errorf("escalation email type = %s, want %s", esc.EmailType, model.EmailTypeEscalation)
				}
				if esc.Status != model.EmailPendingApproval {
					t.Errorf("escalation email status = %s, want %s", esc.Status, model.EmailPendingApproval)
				}
				if esc.ParentEmailID == "" {
					t.Error("escalation email ParentEmailID is empty")
				}
				if esc.Recipient == "" {
					t.Error("escalation email Recipient is empty")
				}
				if esc.EscalateAfter == nil {
					t.Error("escalation email EscalateAfter is nil")
				}
				if esc.ID == "" {
					t.Error("escalation email ID is empty")
				}
			}

			// Verify original email was marked as escalated.
			if tt.wantOriginalNotes != "" {
				for _, e := range tt.dueEmails {
					stored := s.outgoingEmails[e.ID]
					if stored.ResponseNotes != tt.wantOriginalNotes {
						t.Errorf("original email ResponseNotes = %q, want %q", stored.ResponseNotes, tt.wantOriginalNotes)
					}
				}
			}
		})
	}
}

func TestEscalateNow(t *testing.T) {
	now := time.Now().UTC()
	pastDate := now.Add(-10 * 24 * time.Hour)
	sentAt := pastDate

	s := newMockStore()
	s.reports["report-1"] = &model.Report{
		ID:            "report-1",
		Domain:        "bad.example.com",
		URLs:          []string{"https://bad.example.com/page1"},
		ViolationType: model.ViolationHarassment,
		Description:   "Harassment content",
	}
	s.upstreamCache[65001] = []int{174}

	email := &model.OutgoingEmail{
		ID:            "email-esc-now",
		ReportID:      "report-1",
		Recipient:     "abuse@hosting.example.com",
		RecipientOrg:  "HOSTING-EXAMPLE",
		TargetASN:     65001,
		EmailType:     model.EmailTypeInitialReport,
		Status:        model.EmailSent,
		SentAt:        &sentAt,
		ResponseNotes: "Replied by noreply@hosting.example.com at 2026-01-01T00:00:00Z",
		CreatedAt:     pastDate,
	}
	s.outgoingEmails[email.ID] = email

	ac := &mockAbuseContactLookup{contacts: map[int]string{
		174: "abuse@cogent.net",
	}}
	engine := NewEngine(s, ac, 7, testLogger())

	created, err := engine.EscalateNow(context.Background(), "email-esc-now")
	if err != nil {
		t.Fatalf("EscalateNow failed: %v", err)
	}
	if created != 1 {
		t.Errorf("EscalateNow created %d emails, want 1", created)
	}

	// Verify original email's ResponseNotes was first cleared, then set to "escalated".
	stored := s.outgoingEmails["email-esc-now"]
	if stored.ResponseNotes != "escalated" {
		t.Errorf("original email ResponseNotes = %q, want %q", stored.ResponseNotes, "escalated")
	}

	// Verify escalation was created.
	escalations := s.createdEscalations()
	if len(escalations) != 1 {
		t.Fatalf("got %d escalation emails, want 1", len(escalations))
	}
	if escalations[0].Recipient != "abuse@cogent.net" {
		t.Errorf("escalation recipient = %q, want %q", escalations[0].Recipient, "abuse@cogent.net")
	}
}

func TestEscalationBodyContainsContactHistory(t *testing.T) {
	now := time.Now().UTC()
	pastDate := now.Add(-14 * 24 * time.Hour)
	sentAt := pastDate
	replySentAt := pastDate.Add(1 * 24 * time.Hour)

	s := newMockStore()
	s.reports["report-1"] = &model.Report{
		ID:            "report-1",
		Domain:        "bad.example.com",
		URLs:          []string{"https://bad.example.com/page1"},
		ViolationType: model.ViolationHarassment,
		Description:   "Harassment content",
	}
	s.upstreamCache[174] = []int{3356}

	// Initial email that was sent and received a reply.
	initialEmail := &model.OutgoingEmail{
		ID:            "email-initial",
		ReportID:      "report-1",
		Recipient:     "abuse@hosting.example.com",
		RecipientOrg:  "HOSTING-EXAMPLE",
		TargetASN:     65001,
		EmailType:     model.EmailTypeInitialReport,
		Status:        model.EmailSent,
		SentAt:        &sentAt,
		ResponseNotes: "escalated",
		CreatedAt:     pastDate,
	}
	s.outgoingEmails[initialEmail.ID] = initialEmail

	// Simulated first escalation email that's now due.
	escDate := pastDate.Add(7 * 24 * time.Hour)
	escSentAt := escDate
	firstEscEmail := &model.OutgoingEmail{
		ID:            "email-esc-1",
		ReportID:      "report-1",
		ParentEmailID: "email-initial",
		Recipient:     "abuse@transit.example.com",
		RecipientOrg:  "AS174",
		TargetASN:     174,
		EmailType:     model.EmailTypeEscalation,
		Status:        model.EmailSent,
		SentAt:        &escSentAt,
		CreatedAt:     escDate,
	}
	s.outgoingEmails[firstEscEmail.ID] = firstEscEmail

	// Reply to the initial email.
	s.emailReplies[initialEmail.ID] = []*model.EmailReply{
		{
			ID:              "reply-1",
			OutgoingEmailID: initialEmail.ID,
			FromAddress:     "noreply@hosting.example.com",
			Body:            "We have reviewed your report and will not take action.",
			CreatedAt:       replySentAt,
		},
	}

	s.dueEmails = []*model.OutgoingEmail{firstEscEmail}

	ac := &mockAbuseContactLookup{contacts: map[int]string{
		3356: "abuse@lumen.com",
	}}
	engine := NewEngine(s, ac, 7, testLogger())

	engine.checkAndEscalate(context.Background())

	escalations := s.createdEscalations()
	// Filter to only new escalations (not the pre-existing firstEscEmail).
	var newEscalations []*model.OutgoingEmail
	for _, e := range escalations {
		if e.ID != "email-esc-1" {
			newEscalations = append(newEscalations, e)
		}
	}

	if len(newEscalations) != 1 {
		t.Fatalf("got %d new escalation emails, want 1", len(newEscalations))
	}

	body := newEscalations[0].EmailBody

	// Verify contact history section exists.
	if !strings.Contains(body, "== Contact History ==") {
		t.Error("escalation body missing Contact History section")
	}

	// Verify the initial report is mentioned.
	if !strings.Contains(body, "abuse@hosting.example.com") {
		t.Error("escalation body missing reference to initial abuse contact")
	}

	// Verify the reply text is included.
	if !strings.Contains(body, "will not take action") {
		t.Error("escalation body missing reply text from downstream provider")
	}

	// Verify original report details are present.
	if !strings.Contains(body, "== Original Report Details ==") {
		t.Error("escalation body missing Original Report Details section")
	}
}

func TestEscalationBodyContainsPeerNotification(t *testing.T) {
	now := time.Now().UTC()
	pastDate := now.Add(-10 * 24 * time.Hour)
	sentAt := pastDate

	s := newMockStore()
	s.reports["report-1"] = &model.Report{
		ID:            "report-1",
		Domain:        "bad.example.com",
		URLs:          []string{"https://bad.example.com/page1"},
		ViolationType: model.ViolationHarassment,
		Description:   "Harassment content",
	}
	s.upstreamCache[65001] = []int{174, 3356, 6939}

	email := &model.OutgoingEmail{
		ID:           "email-peer",
		ReportID:     "report-1",
		Recipient:    "abuse@hosting.example.com",
		RecipientOrg: "HOSTING-EXAMPLE",
		TargetASN:    65001,
		EmailType:    model.EmailTypeInitialReport,
		Status:       model.EmailSent,
		SentAt:       &sentAt,
		CreatedAt:    pastDate,
	}
	s.outgoingEmails[email.ID] = email
	s.dueEmails = []*model.OutgoingEmail{email}

	ac := &mockAbuseContactLookup{contacts: map[int]string{
		174:  "abuse@cogent.net",
		3356: "abuse@lumen.com",
		6939: "abuse@he.net",
	}}
	engine := NewEngine(s, ac, 7, testLogger())

	engine.checkAndEscalate(context.Background())

	escalations := s.createdEscalations()
	if len(escalations) != 3 {
		t.Fatalf("got %d escalation emails, want 3", len(escalations))
	}

	// Each escalation should mention the other two as peers.
	for _, esc := range escalations {
		if !strings.Contains(esc.EmailBody, "== Peer Escalations ==") {
			t.Errorf("escalation to AS%d missing Peer Escalations section", esc.TargetASN)
		}

		// Count how many other peers are mentioned.
		peerCount := 0
		for _, otherEsc := range escalations {
			if otherEsc.TargetASN != esc.TargetASN {
				if strings.Contains(esc.EmailBody, otherEsc.Recipient) {
					peerCount++
				}
			}
		}
		if peerCount != 2 {
			t.Errorf("escalation to AS%d mentions %d peers, want 2", esc.TargetASN, peerCount)
		}
	}
}

func TestEscalationBodyContainsBoilerplate(t *testing.T) {
	now := time.Now().UTC()
	pastDate := now.Add(-10 * 24 * time.Hour)
	sentAt := pastDate

	s := newMockStore()
	s.reports["report-1"] = &model.Report{
		ID:            "report-1",
		Domain:        "kiwifarms.net",
		URLs:          []string{"https://kiwifarms.net/threads/example"},
		ViolationType: model.ViolationHarassment,
		Description:   "Harassment content",
	}
	s.upstreamCache[65001] = []int{174}

	email := &model.OutgoingEmail{
		ID:           "email-bp",
		ReportID:     "report-1",
		Recipient:    "abuse@hosting.example.com",
		RecipientOrg: "HOSTING-EXAMPLE",
		TargetASN:    65001,
		EmailType:    model.EmailTypeInitialReport,
		Status:       model.EmailSent,
		SentAt:       &sentAt,
		CreatedAt:    pastDate,
	}
	s.outgoingEmails[email.ID] = email
	s.dueEmails = []*model.OutgoingEmail{email}

	ac := &mockAbuseContactLookup{contacts: map[int]string{
		174: "abuse@cogent.net",
	}}
	engine := NewEngine(s, ac, 7, testLogger())
	engine.SetBoilerplate(boilerplate.NewDB())

	engine.checkAndEscalate(context.Background())

	escalations := s.createdEscalations()
	if len(escalations) != 1 {
		t.Fatalf("got %d escalation emails, want 1", len(escalations))
	}

	body := escalations[0].EmailBody
	if !strings.Contains(body, "== Context regarding Kiwi Farms ==") {
		t.Error("escalation body missing boilerplate section for Kiwi Farms")
	}
	if !strings.Contains(body, "harassment and doxxing forum") {
		t.Error("escalation body missing Kiwi Farms summary content")
	}
}

func TestContextCancellationStopsEngine(t *testing.T) {
	s := newMockStore()
	ac := &mockAbuseContactLookup{contacts: map[int]string{}}
	engine := NewEngine(s, ac, 7, testLogger())
	engine.SetTickInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()

	// Let a few ticks pass.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Run() returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after context cancellation")
	}
}
