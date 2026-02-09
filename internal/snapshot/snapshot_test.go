package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripHTML(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain text",
			in:   "hello world",
			want: "hello world",
		},
		{
			name: "simple tags",
			in:   "<p>hello</p>",
			want: "hello",
		},
		{
			name: "script removed",
			in:   "<p>before</p><script>alert('xss')</script><p>after</p>",
			want: "beforeafter",
		},
		{
			name: "style removed",
			in:   "<style>body{color:red}</style><p>visible</p>",
			want: "visible",
		},
		{
			name: "entities decoded",
			in:   "a &amp; b &lt; c &gt; d",
			want: "a & b < c > d",
		},
		{
			name: "whitespace collapsed",
			in:   "hello    world\n\n\nfoo",
			want: "hello world foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripHTML(tt.in)
			if got != tt.want {
				t.Errorf("StripHTML(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTorBinarySnapshotter(t *testing.T) {
	// Create a fake tor-fetcher binary (shell script) in a temp dir.
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "tor-fetcher")

	tests := []struct {
		name       string
		script     string
		wantErr    bool
		wantSubstr string
	}{
		{
			name:       "success",
			script:     "#!/bin/sh\necho '<html><body><p>Hello from Tor</p></body></html>'",
			wantSubstr: "Hello from Tor",
		},
		{
			name:    "exit error",
			script:  "#!/bin/sh\necho 'fatal: connection refused' >&2\nexit 1",
			wantErr: true,
		},
		{
			name:       "passes target flag",
			script:     "#!/bin/sh\necho \"fetched: $2\"", // $1=-target, $2=URL
			wantSubstr: "fetched: https://example.onion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(fakeBin, []byte(tt.script), 0o755); err != nil {
				t.Fatal(err)
			}

			s := NewTorBinarySnapshotter(fakeBin, "")
			got, err := s.Snapshot(context.Background(), "https://example.onion")

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("output %q does not contain %q", got, tt.wantSubstr)
			}
		})
	}
}

func TestTorBinarySnapshotter_BinaryNotFound(t *testing.T) {
	s := NewTorBinarySnapshotter("/nonexistent/tor-fetcher", "")
	_, err := s.Snapshot(context.Background(), "https://example.onion")
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestTorBinarySnapshotter_Timeout(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "tor-fetcher")
	script := "#!/bin/sh\nsleep 60"
	if err := os.WriteFile(fakeBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	s := NewTorBinarySnapshotter(fakeBin, "")
	s.timeout = 1 // 1 nanosecond — will expire immediately

	ctx := context.Background()
	_, err := s.Snapshot(ctx, "https://example.onion")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
