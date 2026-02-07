// Package snapshot provides URL text snapshotting for evidentiary purposes.
// It uses endharassment/tor-fetcher to crawl URLs (including .onion sites
// with PoW challenges) and extracts text-only content.
package snapshot

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// maxBodyBytes is the maximum response body size we'll read.
const maxBodyBytes = 1 << 20 // 1 MiB

// Fetcher abstracts the HTTP fetch operation so we can use tor-fetcher
// or a regular HTTP client.
type Fetcher interface {
	Fetch(target, referer string) (*http.Response, error)
}

// TorSnapshotter uses a Fetcher (typically tor-fetcher's TorClient) to
// snapshot URLs and extract text content.
type TorSnapshotter struct {
	fetcher Fetcher
	timeout time.Duration
}

// NewTorSnapshotter creates a snapshotter backed by the given Fetcher.
func NewTorSnapshotter(f Fetcher) *TorSnapshotter {
	return &TorSnapshotter{
		fetcher: f,
		timeout: 30 * time.Second,
	}
}

// Snapshot fetches a URL and extracts text-only content from the HTML.
func (s *TorSnapshotter) Snapshot(_ context.Context, targetURL string) (string, error) {
	resp, err := s.fetcher.Fetch(targetURL, "")
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", targetURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	text := StripHTML(string(body))
	// Truncate to a reasonable size for storage.
	if len(text) > 50000 {
		text = text[:50000] + "\n[truncated]"
	}

	return text, nil
}

// PlainHTTPSnapshotter uses a standard net/http client for non-onion URLs.
type PlainHTTPSnapshotter struct {
	client *http.Client
}

// NewPlainHTTPSnapshotter creates a snapshotter using a plain HTTP client.
func NewPlainHTTPSnapshotter() *PlainHTTPSnapshotter {
	return &PlainHTTPSnapshotter{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Snapshot fetches a URL and extracts text-only content.
func (s *PlainHTTPSnapshotter) Snapshot(ctx context.Context, targetURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "EndHarassment-ReportingWizard/1.0 (abuse report evidence snapshot)")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", targetURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	text := StripHTML(string(body))
	if len(text) > 50000 {
		text = text[:50000] + "\n[truncated]"
	}

	return text, nil
}

// StripHTML removes HTML tags and extracts visible text content.
// This is a simple implementation that handles common cases.
func StripHTML(s string) string {
	var b strings.Builder
	inTag := false
	inScript := false
	inStyle := false
	prevSpace := false

	lower := strings.ToLower(s)

	for i := 0; i < len(s); i++ {
		c := s[i]

		// Check for script/style opening tags.
		if c == '<' {
			rest := strings.ToLower(s[i:])
			if strings.HasPrefix(rest, "<script") {
				inScript = true
			} else if strings.HasPrefix(rest, "<style") {
				inStyle = true
			}
			_ = lower // avoid unused warning
			inTag = true
			continue
		}

		if c == '>' {
			// Check for script/style closing tags.
			// Look back for </script> or </style>.
			tagContent := ""
			for j := i; j >= 0 && j >= i-20; j-- {
				if s[j] == '<' {
					tagContent = strings.ToLower(s[j : i+1])
					break
				}
			}
			if strings.HasPrefix(tagContent, "</script") {
				inScript = false
			} else if strings.HasPrefix(tagContent, "</style") {
				inStyle = false
			}
			inTag = false
			continue
		}

		if inTag || inScript || inStyle {
			continue
		}

		// Handle HTML entities.
		if c == '&' {
			entity := ""
			for j := i; j < len(s) && j < i+10; j++ {
				entity += string(s[j])
				if s[j] == ';' {
					break
				}
			}
			switch strings.ToLower(entity) {
			case "&amp;":
				b.WriteByte('&')
				i += len(entity) - 1
				prevSpace = false
				continue
			case "&lt;":
				b.WriteByte('<')
				i += len(entity) - 1
				prevSpace = false
				continue
			case "&gt;":
				b.WriteByte('>')
				i += len(entity) - 1
				prevSpace = false
				continue
			case "&quot;":
				b.WriteByte('"')
				i += len(entity) - 1
				prevSpace = false
				continue
			case "&nbsp;":
				b.WriteByte(' ')
				i += len(entity) - 1
				prevSpace = true
				continue
			}
		}

		// Collapse whitespace.
		if unicode.IsSpace(rune(c)) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}

		b.WriteByte(c)
		prevSpace = false
	}

	// Clean up: trim and collapse blank lines.
	lines := strings.Split(b.String(), "\n")
	var cleaned []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}

	return strings.Join(cleaned, "\n")
}
