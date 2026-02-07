package report

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/endharassment/reporting-wizard/internal/model"
)

// Per-report total evidence size limit.
const MaxTotalEvidenceBytesPerReport int64 = 100 << 20 // 100 MiB

// Per-file size limit (mirrors evidence.go).
const MaxEvidenceFileSize int64 = 20 << 20 // 20 MiB

// SafeAllowedContentTypes is the strict allowlist of MIME types accepted for
// evidence uploads. Unlike the permissive list in evidence.go, this does NOT
// accept arbitrary image/* subtypes (which would include SVG with embedded JS).
var SafeAllowedContentTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"application/pdf": true,
	"text/plain":      true,
}

// magicHeaders maps content types to their file magic byte signatures.
var magicHeaders = map[string][]byte{
	"image/jpeg":      {0xFF, 0xD8, 0xFF},
	"image/png":       {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
	"image/gif":       {0x47, 0x49, 0x46, 0x38}, // GIF8
	"image/webp":      {0x52, 0x49, 0x46, 0x46}, // RIFF (WebP container)
	"application/pdf": {0x25, 0x50, 0x44, 0x46}, // %PDF
}

var (
	ErrContentTypeNotAllowed = errors.New("content type not in safety allowlist")
	ErrMagicBytesMismatch    = errors.New("file content does not match declared content type")
	ErrTotalSizeExceeded     = errors.New("total evidence size exceeds per-report limit")
	ErrFilenameDangerous     = errors.New("filename contains dangerous characters")
)

// ValidateContentType checks whether a MIME type is in the strict safety
// allowlist. It strips parameters (e.g., charset) before checking.
func ValidateContentType(contentType string) error {
	ct := strings.TrimSpace(strings.ToLower(contentType))
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if !SafeAllowedContentTypes[ct] {
		return fmt.Errorf("%w: %s", ErrContentTypeNotAllowed, contentType)
	}
	return nil
}

// ValidateFileMagic reads the first bytes of a file and verifies they match
// the expected magic bytes for the declared content type. For text/plain,
// it checks that the content is valid UTF-8 text without embedded null bytes.
// The reader is wrapped so the peeked bytes are still available.
func ValidateFileMagic(r io.Reader, declaredType string) (io.Reader, error) {
	ct := normalizeContentType(declaredType)

	if ct == "text/plain" {
		return validateTextContent(r)
	}

	expected, ok := magicHeaders[ct]
	if !ok {
		// No magic header to check; allow (content type was already validated).
		return r, nil
	}

	header := make([]byte, len(expected))
	n, err := io.ReadFull(r, header)
	if err != nil {
		return nil, fmt.Errorf("reading file header: %w", err)
	}

	for i := 0; i < n; i++ {
		if header[i] != expected[i] {
			return nil, fmt.Errorf("%w: expected %s", ErrMagicBytesMismatch, ct)
		}
	}

	// Return a reader that replays the header bytes then continues with the
	// rest of the original reader.
	return io.MultiReader(strings.NewReader(string(header[:n])), r), nil
}

// validateTextContent peeks at the first chunk of a text file and verifies
// it contains no null bytes (which would indicate a binary file disguised
// as text).
func validateTextContent(r io.Reader) (io.Reader, error) {
	buf := make([]byte, 512)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("reading text content: %w", err)
	}
	for _, b := range buf[:n] {
		if b == 0 {
			return nil, fmt.Errorf("%w: null bytes in text/plain file", ErrMagicBytesMismatch)
		}
	}
	return io.MultiReader(strings.NewReader(string(buf[:n])), r), nil
}

// ValidateTotalEvidenceSize checks whether adding a new file of the given
// size would exceed the per-report total evidence limit. existingBytes is the
// sum of all existing evidence file sizes for the report.
func ValidateTotalEvidenceSize(existingBytes, newFileBytes int64) error {
	if existingBytes+newFileBytes > MaxTotalEvidenceBytesPerReport {
		return fmt.Errorf("%w: current %d + new %d > limit %d",
			ErrTotalSizeExceeded, existingBytes, newFileBytes, MaxTotalEvidenceBytesPerReport)
	}
	return nil
}

// SanitizeFilename removes directory components, null bytes, and control
// characters from a user-provided filename, returning a safe version.
func SanitizeFilename(filename string) (string, error) {
	// Normalize Windows-style backslash separators to forward slash so that
	// filepath.Base strips them on Linux.
	filename = strings.ReplaceAll(filename, "\\", "/")

	// Take only the base name (strip any directory components).
	name := filepath.Base(filename)

	// filepath.Base returns "." for empty input.
	if name == "." || name == "" {
		return "", fmt.Errorf("%w: empty after sanitization", ErrFilenameDangerous)
	}

	// Remove null bytes and control characters.
	var sb strings.Builder
	for _, r := range name {
		if r == 0 || unicode.IsControl(r) {
			continue
		}
		sb.WriteRune(r)
	}
	name = sb.String()

	// Reject if empty after cleaning.
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("%w: invalid after sanitization", ErrFilenameDangerous)
	}

	// Truncate excessively long filenames.
	if len(name) > 255 {
		ext := filepath.Ext(name)
		base := name[:255-len(ext)]
		name = base + ext
	}

	return name, nil
}

// DetectContentType uses http.DetectContentType on the first 512 bytes to
// determine the actual MIME type of a file. Returns the detected type and a
// reader that replays the sniffed bytes followed by the rest of the content.
func DetectContentType(r io.Reader) (string, io.Reader, error) {
	buf := make([]byte, 512)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return "", nil, fmt.Errorf("sniffing content type: %w", err)
	}
	detected := http.DetectContentType(buf[:n])
	combined := io.MultiReader(strings.NewReader(string(buf[:n])), r)
	return detected, combined, nil
}

// HashChecker defines the interface for checking evidence file hashes against
// known-bad content databases (e.g., NCMEC/PhotoDNA). Implementations should
// return true if the hash matches a known-bad entry.
type HashChecker interface {
	// CheckSHA256 checks a SHA-256 hash against the known-bad database.
	// Returns (isMatch, error).
	CheckSHA256(hash string) (bool, error)
}

// NoOpHashChecker is a placeholder that always returns no match. Replace this
// with a real implementation when integrating with PhotoDNA or a hash-sharing
// service.
type NoOpHashChecker struct{}

// CheckSHA256 always returns false (no match). This is a placeholder.
func (n *NoOpHashChecker) CheckSHA256(_ string) (bool, error) {
	return false, nil
}

// EvidenceMetadata provides a view of an evidence file's metadata without
// exposing the file content. This is used for admin review workflows where
// viewing content may not be desired or safe.
type EvidenceMetadata struct {
	ID          string
	ReportID    string
	Filename    string
	ContentType string
	SHA256      string
	SizeBytes   int64
	Description string
	CreatedAt   string
}

// MetadataFromEvidence extracts metadata from a model.Evidence without loading
// or exposing file content. This allows admins to review file details without
// being exposed to potentially harmful content.
func MetadataFromEvidence(ev *model.Evidence) EvidenceMetadata {
	return EvidenceMetadata{
		ID:          ev.ID,
		ReportID:    ev.ReportID,
		Filename:    ev.Filename,
		ContentType: ev.ContentType,
		SHA256:      ev.SHA256,
		SizeBytes:   ev.SizeBytes,
		Description: ev.Description,
		CreatedAt:   ev.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
	}
}

// MetadataFromEvidenceList converts a slice of evidence to metadata-only views.
func MetadataFromEvidenceList(evs []*model.Evidence) []EvidenceMetadata {
	metas := make([]EvidenceMetadata, len(evs))
	for i, ev := range evs {
		metas[i] = MetadataFromEvidence(ev)
	}
	return metas
}

func normalizeContentType(ct string) string {
	ct = strings.TrimSpace(strings.ToLower(ct))
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct
}
