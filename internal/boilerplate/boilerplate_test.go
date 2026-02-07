package boilerplate

import "testing"

func TestLookup(t *testing.T) {
	db := NewDB()

	tests := []struct {
		name      string
		domain    string
		wantMatch bool
		wantName  string
	}{
		{
			name:      "exact primary domain match",
			domain:    "kiwifarms.net",
			wantMatch: true,
			wantName:  "Kiwi Farms",
		},
		{
			name:      "exact alias match",
			domain:    "kiwifarms.st",
			wantMatch: true,
			wantName:  "Kiwi Farms",
		},
		{
			name:      "case insensitive match",
			domain:    "KiwiFarms.Net",
			wantMatch: true,
			wantName:  "Kiwi Farms",
		},
		{
			name:      "wildcard subdomain match",
			domain:    "forum.kiwifarms.net",
			wantMatch: true,
			wantName:  "Kiwi Farms",
		},
		{
			name:      "wildcard with different TLD",
			domain:    "kiwifarms.xyz",
			wantMatch: true,
			wantName:  "Kiwi Farms",
		},
		{
			name:      "wildcard subdomain with different TLD",
			domain:    "www.kiwifarms.co",
			wantMatch: true,
			wantName:  "Kiwi Farms",
		},
		{
			name:      "nested subdomain match",
			domain:    "a.b.kiwifarms.net",
			wantMatch: true,
			wantName:  "Kiwi Farms",
		},
		{
			name:      "no match for unrelated domain",
			domain:    "example.com",
			wantMatch: false,
		},
		{
			name:      "no match for partial name",
			domain:    "notkiwifarms.net",
			wantMatch: false,
		},
		{
			name:      "no match for empty domain",
			domain:    "",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := db.Lookup(tt.domain)
			if tt.wantMatch {
				if info == nil {
					t.Fatal("expected match, got nil")
				}
				if info.DisplayName != tt.wantName {
					t.Errorf("DisplayName = %q, want %q", info.DisplayName, tt.wantName)
				}
				if info.Summary == "" {
					t.Error("Summary should not be empty")
				}
				if info.Context == "" {
					t.Error("Context should not be empty")
				}
			} else {
				if info != nil {
					t.Errorf("expected no match, got %+v", info)
				}
			}
		})
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		domain  string
		want    bool
	}{
		{"leading wildcard match", "*.example.com", "sub.example.com", true},
		{"leading wildcard exact", "*.example.com", "example.com", true},
		{"leading wildcard no match", "*.example.com", "other.com", false},
		{"trailing wildcard match", "example.*", "example.com", true},
		{"trailing wildcard match org", "example.*", "example.org", true},
		{"trailing wildcard no match", "example.*", "other.com", false},
		{"both wildcards match", "*.kiwifarms.*", "forum.kiwifarms.net", true},
		{"both wildcards bare domain", "*.kiwifarms.*", "kiwifarms.net", true},
		{"both wildcards no match", "*.kiwifarms.*", "example.com", false},
		{"exact pattern", "example.com", "example.com", true},
		{"exact pattern no match", "example.com", "other.com", false},
		{"no false prefix match", "*.kiwifarms.*", "notkiwifarms.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchWildcard(tt.pattern, tt.domain)
			if got != tt.want {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v", tt.pattern, tt.domain, got, tt.want)
			}
		})
	}
}
