package report

import (
	"strings"
	"testing"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
)

func TestValidateContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{"jpeg allowed", "image/jpeg", false},
		{"png allowed", "image/png", false},
		{"gif allowed", "image/gif", false},
		{"webp allowed", "image/webp", false},
		{"pdf allowed", "application/pdf", false},
		{"text allowed", "text/plain", false},
		{"text with charset", "text/plain; charset=utf-8", false},
		{"svg rejected", "image/svg+xml", true},
		{"tiff rejected", "image/tiff", true},
		{"bmp rejected", "image/bmp", true},
		{"video rejected", "video/mp4", true},
		{"html rejected", "text/html", true},
		{"executable rejected", "application/octet-stream", true},
		{"empty rejected", "", true},
		{"uppercase normalized", "IMAGE/JPEG", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContentType(tt.contentType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContentType(%q) error = %v, wantErr %v", tt.contentType, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFileMagic(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		contentType string
		wantErr     bool
	}{
		{
			name:        "valid jpeg",
			content:     "\xFF\xD8\xFF\xE0rest of jpeg data",
			contentType: "image/jpeg",
			wantErr:     false,
		},
		{
			name:        "invalid jpeg magic",
			content:     "\x89PNG\r\n\x1a\nthis is actually png",
			contentType: "image/jpeg",
			wantErr:     true,
		},
		{
			name:        "valid png",
			content:     "\x89PNG\r\n\x1a\nrest of png data",
			contentType: "image/png",
			wantErr:     false,
		},
		{
			name:        "valid gif",
			content:     "GIF89a rest of gif data",
			contentType: "image/gif",
			wantErr:     false,
		},
		{
			name:        "valid pdf",
			content:     "%PDF-1.4 rest of pdf data",
			contentType: "application/pdf",
			wantErr:     false,
		},
		{
			name:        "valid text",
			content:     "This is plain text content",
			contentType: "text/plain",
			wantErr:     false,
		},
		{
			name:        "text with null bytes rejected",
			content:     "text with \x00 null byte",
			contentType: "text/plain",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.content)
			_, err := ValidateFileMagic(r, tt.contentType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFileMagic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTotalEvidenceSize(t *testing.T) {
	tests := []struct {
		name     string
		existing int64
		newFile  int64
		wantErr  bool
	}{
		{"within limit", 50 << 20, 30 << 20, false},
		{"exactly at limit", 80 << 20, 20 << 20, false},
		{"exceeds limit", 90 << 20, 20 << 20, true},
		{"zero existing", 0, 20 << 20, false},
		{"zero new", 50 << 20, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTotalEvidenceSize(tt.existing, tt.newFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTotalEvidenceSize(%d, %d) error = %v, wantErr %v",
					tt.existing, tt.newFile, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"simple name", "photo.jpg", "photo.jpg", false},
		{"strips directory", "/etc/passwd", "passwd", false},
		{"strips relative path", "../../../etc/passwd", "passwd", false},
		{"strips windows path", `C:\Users\evil\file.txt`, "file.txt", false},
		{"removes null bytes", "file\x00name.jpg", "filename.jpg", false},
		{"removes control chars", "file\x01\x02name.jpg", "filename.jpg", false},
		{"empty string rejected", "", "", true},
		{"dot rejected", ".", "", true},
		{"dotdot rejected", "..", "", true},
		{"preserves spaces", "my file (1).jpg", "my file (1).jpg", false},
		{"preserves unicode", "photo_\u00e9vidence.png", "photo_\u00e9vidence.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeFilename(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SanitizeFilename(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilenameLongName(t *testing.T) {
	long := strings.Repeat("a", 300) + ".jpg"
	got, err := SanitizeFilename(long)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) > 255 {
		t.Errorf("filename length %d exceeds 255", len(got))
	}
	if !strings.HasSuffix(got, ".jpg") {
		t.Errorf("expected .jpg extension, got %q", got)
	}
}

func TestMetadataFromEvidence(t *testing.T) {
	ev := &model.Evidence{
		ID:          "ev-123",
		ReportID:    "rpt-456",
		Filename:    "screenshot.png",
		ContentType: "image/png",
		SHA256:      "abcdef1234567890",
		SizeBytes:   12345,
		Description: "Screenshot of harassment",
		CreatedAt:   time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	meta := MetadataFromEvidence(ev)

	if meta.ID != ev.ID {
		t.Errorf("ID = %q, want %q", meta.ID, ev.ID)
	}
	if meta.ReportID != ev.ReportID {
		t.Errorf("ReportID = %q, want %q", meta.ReportID, ev.ReportID)
	}
	if meta.Filename != ev.Filename {
		t.Errorf("Filename = %q, want %q", meta.Filename, ev.Filename)
	}
	if meta.SHA256 != ev.SHA256 {
		t.Errorf("SHA256 = %q, want %q", meta.SHA256, ev.SHA256)
	}
	if meta.SizeBytes != ev.SizeBytes {
		t.Errorf("SizeBytes = %d, want %d", meta.SizeBytes, ev.SizeBytes)
	}
}

func TestMetadataFromEvidenceList(t *testing.T) {
	evs := []*model.Evidence{
		{ID: "ev-1", Filename: "a.png", CreatedAt: time.Now()},
		{ID: "ev-2", Filename: "b.jpg", CreatedAt: time.Now()},
	}
	metas := MetadataFromEvidenceList(evs)
	if len(metas) != 2 {
		t.Fatalf("got %d metadata entries, want 2", len(metas))
	}
	if metas[0].ID != "ev-1" || metas[1].ID != "ev-2" {
		t.Error("metadata IDs don't match input evidence")
	}
}

func TestNoOpHashChecker(t *testing.T) {
	checker := &NoOpHashChecker{}
	match, err := checker.CheckSHA256("abcdef1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("NoOpHashChecker should always return false")
	}
}
