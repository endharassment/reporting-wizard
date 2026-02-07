// Package gdrive provides helpers for parsing Google Drive URLs and
// verifying file metadata using the Google Drive API.
package gdrive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"golang.org/x/oauth2"
)

// FileMeta contains the metadata returned by the Drive API for a file.
type FileMeta struct {
	ID          string
	Name        string
	MimeType    string
	Size        int64
	CreatedTime time.Time
}

// driveFileIDPatterns matches common Google Drive URL formats.
var driveFileIDPatterns = []*regexp.Regexp{
	// https://drive.google.com/file/d/FILE_ID/view?usp=sharing
	regexp.MustCompile(`drive\.google\.com/file/d/([a-zA-Z0-9_-]+)`),
	// https://drive.google.com/open?id=FILE_ID
	regexp.MustCompile(`drive\.google\.com/open\?id=([a-zA-Z0-9_-]+)`),
	// https://docs.google.com/document/d/FILE_ID/...
	regexp.MustCompile(`docs\.google\.com/(?:document|spreadsheets|presentation)/d/([a-zA-Z0-9_-]+)`),
}

// IsDriveURL returns true if the URL appears to be a Google Drive URL.
func IsDriveURL(rawURL string) bool {
	return ExtractFileID(rawURL) != ""
}

// ExtractFileID extracts the Google Drive file ID from a URL.
// Returns empty string if the URL is not a recognized Drive URL.
func ExtractFileID(rawURL string) string {
	for _, pat := range driveFileIDPatterns {
		matches := pat.FindStringSubmatch(rawURL)
		if len(matches) >= 2 {
			return matches[1]
		}
	}
	// Also try the id= query parameter for general Drive URLs.
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if parsed.Host == "drive.google.com" || parsed.Host == "www.drive.google.com" {
		if id := parsed.Query().Get("id"); id != "" {
			return id
		}
	}
	return ""
}

// driveFileResponse is the JSON response from the Drive Files.get API.
type driveFileResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	MimeType    string `json:"mimeType"`
	Size        string `json:"size"`
	CreatedTime string `json:"createdTime"`
	Error       *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// GetFileMeta fetches metadata for a Google Drive file using the provided
// OAuth2 token. The token must have the drive.metadata.readonly scope.
// This uses the REST API directly to avoid pulling in the full Google API
// client library.
func GetFileMeta(ctx context.Context, token *oauth2.Token, fileID string) (*FileMeta, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	apiURL := fmt.Sprintf(
		"https://www.googleapis.com/drive/v3/files/%s?fields=id,name,mimeType,size,createdTime",
		url.PathEscape(fileID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("drive API returned %d: %s", resp.StatusCode, body)
	}

	var driveFile driveFileResponse
	if err := json.Unmarshal(body, &driveFile); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	meta := &FileMeta{
		ID:       driveFile.ID,
		Name:     driveFile.Name,
		MimeType: driveFile.MimeType,
	}

	if driveFile.Size != "" {
		fmt.Sscanf(driveFile.Size, "%d", &meta.Size)
	}
	if driveFile.CreatedTime != "" {
		meta.CreatedTime, _ = time.Parse(time.RFC3339, driveFile.CreatedTime)
	}

	return meta, nil
}

// RefreshTokenIfNeeded uses the oauth2 config to refresh the access token
// if it is expired. Returns the potentially-refreshed token.
func RefreshTokenIfNeeded(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
	src := cfg.TokenSource(ctx, token)
	newToken, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}
	return newToken, nil
}
