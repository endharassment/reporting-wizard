package escalation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
)

// mockStore implements store.Store with in-memory maps. Only the methods
// needed by the escalation engine are fully implemented; all others panic.
type mockStore struct {
	mu             sync.Mutex
	reports        map[string]*model.Report
	infraResults   map[string][]*model.InfraResult // keyed by report ID
	outgoingEmails map[string]*model.OutgoingEmail
	dueEmails      []*model.OutgoingEmail
}

func newMockStore() *mockStore {
	return &mockStore{
		reports:        make(map[string]*model.Report),
		infraResults:   make(map[string][]*model.InfraResult),
		outgoingEmails: make(map[string]*model.OutgoingEmail),
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

// createdEscalations returns all emails created with type "escalation".
func (m *mockStore) createdEscalations() []*model.OutgoingEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*model.OutgoingEmail
	for _, e := range m.outgoingEmails {
		if e.EmailType == model.EmailTypeEscalation {
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
func (m *mockStore) UpdateUser(context.Context, *model.User) error { panic("not implemented") }
func (m *mockStore) CreateSession(context.Context, *model.Session) error {
	panic("not implemented")
}
func (m *mockStore) GetSession(context.Context, string) (*model.Session, error) {
	panic("not implemented")
}
func (m *mockStore) DeleteSession(context.Context, string) error { panic("not implemented") }
func (m *mockStore) DeleteExpiredSessions(context.Context) error { panic("not implemented") }
func (m *mockStore) CreateMagicLink(context.Context, *model.MagicLink) error {
	panic("not implemented")
}
func (m *mockStore) GetMagicLink(context.Context, string) (*model.MagicLink, error) {
	panic("not implemented")
}
func (m *mockStore) MarkMagicLinkUsed(context.Context, string) error { panic("not implemented") }
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
func (m *mockStore) GetEvidence(context.Context, string) (*model.Evidence, error) {
	panic("not implemented")
}
func (m *mockStore) ListEvidenceByReport(context.Context, string) ([]*model.Evidence, error) {
	panic("not implemented")
}
func (m *mockStore) GetOutgoingEmail(context.Context, string) (*model.OutgoingEmail, error) {
	panic("not implemented")
}
func (m *mockStore) ListEmailsByReport(context.Context, string) ([]*model.OutgoingEmail, error) {
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
		infraResults        map[string][]*model.InfraResult
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
			infraResults: map[string][]*model.InfraResult{
				"report-1": {
					{
						ID:           "infra-1",
						ReportID:     "report-1",
						IP:           "198.51.100.1",
						ASN:          65001,
						ASNName:      "HOSTING-EXAMPLE",
						UpstreamASNs: []int{174, 3356},
					},
				},
			},
			abuseContacts: map[int]string{
				174:  "abuse@cogent.net",
				3356: "abuse@lumen.com",
			},
			wantEscalationCount: 2,
			wantOriginalNotes:   "escalated",
		},
		{
			name:      "email not yet due is not returned by store",
			dueEmails: []*model.OutgoingEmail{
				// This simulates the store NOT returning this email because
				// escalate_after is in the future. The store's
				// ListEmailsDueForEscalation already filters by time, but
				// we test with an empty list to verify no action is taken.
			},
			reports:             map[string]*model.Report{},
			infraResults:        map[string][]*model.InfraResult{},
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
			infraResults:        map[string][]*model.InfraResult{},
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
			infraResults: map[string][]*model.InfraResult{
				"report-3": {
					{
						ID:           "infra-1",
						ReportID:     "report-3",
						IP:           "198.51.100.1",
						ASN:          65001,
						ASNName:      "HOSTING-EXAMPLE",
						UpstreamASNs: []int{174, 3356},
					},
					{
						ID:           "infra-2",
						ReportID:     "report-3",
						IP:           "198.51.100.2",
						ASN:          65002,
						ASNName:      "HOSTING-TWO",
						UpstreamASNs: []int{3356, 6939},
					},
				},
			},
			abuseContacts: map[int]string{
				174:  "abuse@cogent.net",
				3356: "abuse@lumen.com",
				6939: "abuse@he.net",
			},
			// 3356 appears twice but should only produce one escalation email
			wantEscalationCount: 3,
			wantOriginalNotes:   "escalated",
		},
		{
			name: "duplicate abuse contacts across ASNs are deduplicated",
			dueEmails: []*model.OutgoingEmail{
				{
					ID:            "email-4",
					ReportID:      "report-4",
					Recipient:     "abuse@hosting.example.com",
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
			infraResults: map[string][]*model.InfraResult{
				"report-4": {
					{
						ID:           "infra-1",
						ReportID:     "report-4",
						IP:           "198.51.100.1",
						ASN:          65001,
						UpstreamASNs: []int{174, 3356},
					},
				},
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
			name:      "escalate_after in future is unused because store already filters",
			dueEmails: []*model.OutgoingEmail{
				// Store returned empty because escalate_after is in the future.
			},
			reports:             map[string]*model.Report{},
			infraResults:        map[string][]*model.InfraResult{},
			abuseContacts:       map[int]string{},
			wantEscalationCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMockStore()
			s.dueEmails = tt.dueEmails
			s.reports = tt.reports
			s.infraResults = tt.infraResults

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
