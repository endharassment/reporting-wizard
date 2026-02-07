package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

var testXARFConfig = XARFConfig{
	ReporterOrg:          "End Network Harassment Inc",
	ReporterOrgDomain:    "endharassment.net",
	ReporterContactEmail: "reports@endharassment.net",
	ReporterContactName:  "Abuse Reports Team",
}

var testEmailConfig = EmailConfig{
	XARF:           testXARFConfig,
	FromAddress:    "noreply@endharassment.net",
	FromName:       "End Network Harassment Inc",
	SandboxMode:    true,
	SendGridAPIKey: "test-key",
}

func testReport(vt model.ViolationType) *model.Report {
	return &model.Report{
		ID:            "rpt-001",
		UserID:        "usr-001",
		Domain:        "example.com",
		URLs:          []string{"https://example.com/page1", "https://example.com/page2"},
		ViolationType: vt,
		Description:   "Abusive content targeting an individual.",
		Status:        model.StatusDraft,
		CreatedAt:     time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
	}
}

func testInfraResults() []*model.InfraResult {
	return []*model.InfraResult{
		{
			ID:           "infra-001",
			ReportID:     "rpt-001",
			IP:           "93.184.216.34",
			RecordType:   "A",
			ASN:          15133,
			ASNName:      "EDGECAST",
			BGPPrefix:    "93.184.216.0/24",
			Country:      "US",
			AbuseContact: "abuse@edgecast.com",
			IsCloudflare: false,
		},
	}
}

func testEvidence() []*model.Evidence {
	return []*model.Evidence{
		{
			ID:          "ev-001",
			ReportID:    "rpt-001",
			Filename:    "screenshot.png",
			ContentType: "image/png",
			StoragePath: "/evidence/rpt-001/ev-001",
			SHA256:      "abc123def456",
			SizeBytes:   1024,
			Description: "Screenshot of abusive content",
		},
	}
}

func TestGenerateXARF_ViolationTypes(t *testing.T) {
	tests := []struct {
		name            string
		violationType   model.ViolationType
		wantReportClass string
		wantReportType  string
	}{
		{
			name:            "harassment",
			violationType:   model.ViolationHarassment,
			wantReportClass: "content",
			wantReportType:  "illegal_content",
		},
		{
			name:            "hate_speech",
			violationType:   model.ViolationHateSpeech,
			wantReportClass: "content",
			wantReportType:  "illegal_content",
		},
		{
			name:            "ncii",
			violationType:   model.ViolationNCII,
			wantReportClass: "content",
			wantReportType:  "illegal_content",
		},
		{
			name:            "doxxing",
			violationType:   model.ViolationDoxxing,
			wantReportClass: "content",
			wantReportType:  "illegal_content",
		},
		{
			name:            "copyvio",
			violationType:   model.ViolationCopyvio,
			wantReportClass: "copyright",
			wantReportType:  "copyright_infringement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := testReport(tt.violationType)
			infra := testInfraResults()
			evidence := testEvidence()
			content := map[string]string{"ev-001": "base64content"}

			data, err := GenerateXARF(testXARFConfig, report, infra, evidence, content)
			if err != nil {
				t.Fatalf("GenerateXARF() error = %v", err)
			}

			var xarf XARFReport
			if err := json.Unmarshal(data, &xarf); err != nil {
				t.Fatalf("failed to unmarshal X-ARF: %v", err)
			}

			if xarf.Version != "4" {
				t.Errorf("Version = %q, want %q", xarf.Version, "4")
			}
			if xarf.Report.ReportClass != tt.wantReportClass {
				t.Errorf("ReportClass = %q, want %q", xarf.Report.ReportClass, tt.wantReportClass)
			}
			if xarf.Report.ReportType != tt.wantReportType {
				t.Errorf("ReportType = %q, want %q", xarf.Report.ReportType, tt.wantReportType)
			}
			if xarf.Report.Domain != "example.com" {
				t.Errorf("Domain = %q, want %q", xarf.Report.Domain, "example.com")
			}
			if xarf.Report.SourceIP != "93.184.216.34" {
				t.Errorf("SourceIP = %q, want %q", xarf.Report.SourceIP, "93.184.216.34")
			}
			if len(xarf.Report.URLs) != 2 {
				t.Errorf("URLs count = %d, want 2", len(xarf.Report.URLs))
			}
			if xarf.ReporterInfo.ReporterOrg != "End Network Harassment Inc" {
				t.Errorf("ReporterOrg = %q, want %q", xarf.ReporterInfo.ReporterOrg, "End Network Harassment Inc")
			}
			if len(xarf.Evidence) != 1 {
				t.Fatalf("Evidence count = %d, want 1", len(xarf.Evidence))
			}
			if xarf.Evidence[0].Content != "base64content" {
				t.Errorf("Evidence Content = %q, want %q", xarf.Evidence[0].Content, "base64content")
			}
		})
	}
}

func TestGenerateXARF_LargeEvidenceOmitsContent(t *testing.T) {
	report := testReport(model.ViolationHarassment)
	evidence := []*model.Evidence{
		{
			ID:          "ev-big",
			ReportID:    "rpt-001",
			Filename:    "video.mp4",
			ContentType: "video/mp4",
			SHA256:      "deadbeef",
			SizeBytes:   2 << 20, // 2 MiB > maxInlineEvidenceBytes
			Description: "Video evidence",
		},
	}
	content := map[string]string{"ev-big": "should-not-appear"}

	data, err := GenerateXARF(testXARFConfig, report, nil, evidence, content)
	if err != nil {
		t.Fatalf("GenerateXARF() error = %v", err)
	}

	var xarf XARFReport
	if err := json.Unmarshal(data, &xarf); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(xarf.Evidence) != 1 {
		t.Fatalf("Evidence count = %d, want 1", len(xarf.Evidence))
	}
	if xarf.Evidence[0].Content != "" {
		t.Errorf("expected Content to be omitted for large evidence, got %q", xarf.Evidence[0].Content)
	}
}

func TestHandleUpload_Success(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello world test evidence content")
	reader := bytes.NewReader(content)

	ev, err := HandleUpload(context.Background(), dir, "rpt-001", "screenshot.png", "image/png", reader)
	if err != nil {
		t.Fatalf("HandleUpload() error = %v", err)
	}

	if ev.ReportID != "rpt-001" {
		t.Errorf("ReportID = %q, want %q", ev.ReportID, "rpt-001")
	}
	if ev.Filename != "screenshot.png" {
		t.Errorf("Filename = %q, want %q", ev.Filename, "screenshot.png")
	}
	if ev.ContentType != "image/png" {
		t.Errorf("ContentType = %q, want %q", ev.ContentType, "image/png")
	}
	if ev.SizeBytes != int64(len(content)) {
		t.Errorf("SizeBytes = %d, want %d", ev.SizeBytes, len(content))
	}

	// Verify SHA-256 hash.
	h := sha256.Sum256(content)
	wantHash := hex.EncodeToString(h[:])
	if ev.SHA256 != wantHash {
		t.Errorf("SHA256 = %q, want %q", ev.SHA256, wantHash)
	}

	// Verify file was written to disk.
	stored, err := os.ReadFile(ev.StoragePath)
	if err != nil {
		t.Fatalf("reading stored file: %v", err)
	}
	if !bytes.Equal(stored, content) {
		t.Errorf("stored file content mismatch")
	}

	// Verify file is stored under UUID, not original filename.
	base := filepath.Base(ev.StoragePath)
	if base == "screenshot.png" {
		t.Errorf("file should be stored under UUID, not original filename")
	}
}

func TestHandleUpload_OversizedFile(t *testing.T) {
	dir := t.TempDir()

	// Create a reader that produces just over 20MB.
	oversized := make([]byte, maxEvidenceFileSize+1)
	reader := bytes.NewReader(oversized)

	_, err := HandleUpload(context.Background(), dir, "rpt-001", "big.png", "image/png", reader)
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}
	if err != ErrFileTooLarge {
		t.Errorf("error = %v, want ErrFileTooLarge", err)
	}

	// Verify no file was left behind.
	entries, _ := os.ReadDir(filepath.Join(dir, "rpt-001"))
	if len(entries) != 0 {
		t.Errorf("expected cleanup after rejection, found %d files", len(entries))
	}
}

func TestHandleUpload_DisallowedContentTypes(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{"image/png allowed", "image/png", false},
		{"image/jpeg allowed", "image/jpeg", false},
		{"application/pdf allowed", "application/pdf", false},
		{"text/plain allowed", "text/plain", false},
		{"video/mp4 allowed", "video/mp4", false},
		{"image/svg+xml allowed (image/* wildcard)", "image/svg+xml", false},
		{"application/zip disallowed", "application/zip", true},
		{"text/html disallowed", "text/html", true},
		{"application/javascript disallowed", "application/javascript", true},
		{"empty disallowed", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader([]byte("test"))
			ct := tt.contentType
			if ct == "" {
				_, err := HandleUpload(context.Background(), dir, "rpt-001", "file.bin", "", reader)
				if err == nil {
					t.Fatal("expected error for empty content type")
				}
				return
			}
			_, err := HandleUpload(context.Background(), dir, "rpt-001", "file.bin", ct, reader)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for content type %q, got nil", ct)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for content type %q: %v", ct, err)
			}
		})
	}
}

func TestHandleUpload_ValidationErrors(t *testing.T) {
	dir := t.TempDir()
	reader := bytes.NewReader([]byte("test"))

	tests := []struct {
		name        string
		evidenceDir string
		reportID    string
		filename    string
		contentType string
		wantErr     error
	}{
		{"empty report ID", dir, "", "file.png", "image/png", ErrReportIDEmpty},
		{"empty filename", dir, "rpt-001", "", "image/png", ErrFilenameEmpty},
		{"empty content type", dir, "rpt-001", "file.png", "", ErrContentTypeEmpty},
		{"missing evidence dir", "/nonexistent/path", "rpt-001", "file.png", "image/png", ErrEvidenceDirMissing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HandleUpload(context.Background(), tt.evidenceDir, tt.reportID, tt.filename, tt.contentType, reader)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}
			if err != tt.wantErr && !strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestComposeEmail(t *testing.T) {
	tests := []struct {
		name                string
		violationType       model.ViolationType
		wantSubjectContains string
		wantBodyParts       []string
	}{
		{
			name:                "harassment report",
			violationType:       model.ViolationHarassment,
			wantSubjectContains: "Abuse Report: harassment violation on example.com",
			wantBodyParts: []string{
				"Dear Abuse Team",
				"harassment violation",
				"example.com",
				"https://example.com/page1",
				"Abusive content targeting an individual",
				"X-ARF",
			},
		},
		{
			name:                "copyvio report",
			violationType:       model.ViolationCopyvio,
			wantSubjectContains: "Abuse Report: copyright infringement violation on example.com",
			wantBodyParts: []string{
				"copyright infringement",
				"example.com",
			},
		},
		{
			name:                "ncii report",
			violationType:       model.ViolationNCII,
			wantSubjectContains: "Abuse Report: non-consensual intimate imagery (NCII) violation on example.com",
			wantBodyParts: []string{
				"non-consensual intimate imagery",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := testReport(tt.violationType)
			infra := testInfraResults()
			evidence := testEvidence()
			content := map[string]string{}

			email, err := ComposeEmail(testEmailConfig, report, infra, evidence, content)
			if err != nil {
				t.Fatalf("ComposeEmail() error = %v", err)
			}

			if !strings.Contains(email.EmailSubject, tt.wantSubjectContains) {
				t.Errorf("Subject = %q, want to contain %q", email.EmailSubject, tt.wantSubjectContains)
			}
			if !strings.Contains(email.EmailSubject, "[Ticket:") {
				t.Errorf("Subject = %q, want to contain [Ticket:]", email.EmailSubject)
			}

			for _, part := range tt.wantBodyParts {
				if !strings.Contains(email.EmailBody, part) {
					t.Errorf("Body missing expected text %q", part)
				}
			}

			if email.Recipient != "abuse@edgecast.com" {
				t.Errorf("Recipient = %q, want %q", email.Recipient, "abuse@edgecast.com")
			}
			if email.RecipientOrg != "EDGECAST" {
				t.Errorf("RecipientOrg = %q, want %q", email.RecipientOrg, "EDGECAST")
			}
			if email.TargetASN != 15133 {
				t.Errorf("TargetASN = %d, want %d", email.TargetASN, 15133)
			}
			if email.Status != model.EmailPendingApproval {
				t.Errorf("Status = %q, want %q", email.Status, model.EmailPendingApproval)
			}
			if email.EmailType != model.EmailTypeInitialReport {
				t.Errorf("EmailType = %q, want %q", email.EmailType, model.EmailTypeInitialReport)
			}

			// Verify X-ARF JSON is present and valid.
			var xarf XARFReport
			if err := json.Unmarshal([]byte(email.XARFJson), &xarf); err != nil {
				t.Fatalf("XARFJson is not valid JSON: %v", err)
			}
			if xarf.Version != "4" {
				t.Errorf("XARF Version = %q, want %q", xarf.Version, "4")
			}
		})
	}
}

// mockSendGridSender implements SendGridSender for tests.
type mockSendGridSender struct {
	lastEmail *mail.SGMailV3
	err       error
	result    *SendResult
}

func (m *mockSendGridSender) Send(email *mail.SGMailV3) (*SendResult, error) {
	m.lastEmail = email
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestSendEmail_Success(t *testing.T) {
	report := testReport(model.ViolationHarassment)
	infra := testInfraResults()
	evidence := testEvidence()

	outgoing, err := ComposeEmail(testEmailConfig, report, infra, evidence, nil)
	if err != nil {
		t.Fatalf("ComposeEmail() error = %v", err)
	}

	mock := &mockSendGridSender{
		result: &SendResult{StatusCode: 202, MessageID: "msg-123"},
	}

	result, err := SendEmail(mock, testEmailConfig, outgoing)
	if err != nil {
		t.Fatalf("SendEmail() error = %v", err)
	}
	if result.StatusCode != 202 {
		t.Errorf("StatusCode = %d, want 202", result.StatusCode)
	}
	if result.MessageID != "msg-123" {
		t.Errorf("MessageID = %q, want %q", result.MessageID, "msg-123")
	}

	// Verify the email was constructed correctly.
	if mock.lastEmail == nil {
		t.Fatal("expected email to be sent")
	}

	// Verify sandbox mode is enabled.
	if mock.lastEmail.MailSettings == nil || mock.lastEmail.MailSettings.SandboxMode == nil {
		t.Fatal("expected sandbox mode to be configured")
	}
	if mock.lastEmail.MailSettings.SandboxMode.Enable == nil || !*mock.lastEmail.MailSettings.SandboxMode.Enable {
		t.Error("expected sandbox mode to be enabled")
	}

	// Verify attachment.
	if len(mock.lastEmail.Attachments) != 1 {
		t.Fatalf("Attachments count = %d, want 1", len(mock.lastEmail.Attachments))
	}
	if mock.lastEmail.Attachments[0].Filename != "xarf-report.json" {
		t.Errorf("Attachment filename = %q, want %q", mock.lastEmail.Attachments[0].Filename, "xarf-report.json")
	}
}

func TestSendEmail_Error(t *testing.T) {
	outgoing := &model.OutgoingEmail{
		Recipient:    "abuse@example.com",
		RecipientOrg: "Example",
		EmailSubject: "Test",
		EmailBody:    "Test body",
		XARFJson:     "{}",
	}

	mock := &mockSendGridSender{
		err: fmt.Errorf("connection refused"),
	}

	_, err := SendEmail(mock, testEmailConfig, outgoing)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want to contain 'connection refused'", err)
	}
}

func TestSendEmail_NoSandboxMode(t *testing.T) {
	outgoing := &model.OutgoingEmail{
		Recipient:    "abuse@example.com",
		RecipientOrg: "Example",
		EmailSubject: "Test",
		EmailBody:    "Test body",
		XARFJson:     "{}",
	}

	cfg := testEmailConfig
	cfg.SandboxMode = false

	mock := &mockSendGridSender{
		result: &SendResult{StatusCode: 202, MessageID: "msg-456"},
	}

	_, err := SendEmail(mock, cfg, outgoing)
	if err != nil {
		t.Fatalf("SendEmail() error = %v", err)
	}

	if mock.lastEmail.MailSettings != nil && mock.lastEmail.MailSettings.SandboxMode != nil && mock.lastEmail.MailSettings.SandboxMode.Enable != nil && *mock.lastEmail.MailSettings.SandboxMode.Enable {
		t.Error("sandbox mode should not be enabled when SandboxMode is false")
	}
}
