package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/google/uuid"
)

const maxEvidenceFileSize int64 = 20 << 20 // 20 MiB

// allowedContentTypes lists MIME types accepted for evidence uploads.
var allowedContentTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"image/tiff":      true,
	"image/bmp":       true,
	"application/pdf": true,
	"text/plain":      true,
	"video/mp4":       true,
}

var (
	ErrFileTooLarge       = errors.New("evidence file exceeds maximum size of 20MB")
	ErrDisallowedType     = errors.New("content type not allowed for evidence upload")
	ErrContentTypeEmpty   = errors.New("content type must not be empty")
	ErrFilenameEmpty      = errors.New("filename must not be empty")
	ErrReportIDEmpty      = errors.New("report ID must not be empty")
	ErrEvidenceDirMissing = errors.New("evidence directory does not exist")
)

// isAllowedContentType checks whether a MIME type is permitted. It accepts
// any image/* subtype in addition to the explicit allowlist.
func isAllowedContentType(ct string) bool {
	ct = strings.TrimSpace(strings.ToLower(ct))
	// Strip parameters (e.g. "text/plain; charset=utf-8")
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if allowedContentTypes[ct] {
		return true
	}
	if strings.HasPrefix(ct, "image/") {
		return true
	}
	return false
}

// HandleUpload processes an evidence file upload. It streams the reader to
// disk under evidenceDir, computing a SHA-256 hash as it goes, and returns
// a populated model.Evidence struct.
func HandleUpload(ctx context.Context, evidenceDir string, reportID string, filename string, contentType string, r io.Reader) (*model.Evidence, error) {
	if reportID == "" {
		return nil, ErrReportIDEmpty
	}
	if filename == "" {
		return nil, ErrFilenameEmpty
	}
	if contentType == "" {
		return nil, ErrContentTypeEmpty
	}
	if !isAllowedContentType(contentType) {
		return nil, fmt.Errorf("%w: %s", ErrDisallowedType, contentType)
	}

	// Verify evidence directory exists.
	info, err := os.Stat(evidenceDir)
	if err != nil || !info.IsDir() {
		return nil, ErrEvidenceDirMissing
	}

	// Create report-specific subdirectory.
	reportDir := filepath.Join(evidenceDir, reportID)
	if err := os.MkdirAll(reportDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating report evidence directory: %w", err)
	}

	evidenceID := uuid.New().String()
	storagePath := filepath.Join(reportDir, evidenceID)

	f, err := os.Create(storagePath)
	if err != nil {
		return nil, fmt.Errorf("creating evidence file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	limitedReader := io.LimitReader(r, maxEvidenceFileSize+1)
	written, err := io.Copy(f, io.TeeReader(limitedReader, hasher))
	if err != nil {
		os.Remove(storagePath)
		return nil, fmt.Errorf("writing evidence file: %w", err)
	}
	if written > maxEvidenceFileSize {
		os.Remove(storagePath)
		return nil, ErrFileTooLarge
	}

	if err := f.Close(); err != nil {
		os.Remove(storagePath)
		return nil, fmt.Errorf("closing evidence file: %w", err)
	}

	return &model.Evidence{
		ID:          evidenceID,
		ReportID:    reportID,
		Filename:    filename,
		ContentType: contentType,
		StoragePath: storagePath,
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
		SizeBytes:   written,
		CreatedAt:   time.Now().UTC(),
	}, nil
}
