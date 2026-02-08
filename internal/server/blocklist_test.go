package server

import "testing"

func TestIsDomainBlocked(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		blocked bool
	}{
		{"exact match", "google.com", true},
		{"subdomain match", "docs.google.com", true},
		{"deep subdomain match", "a.b.youtube.com", true},
		{"non-blocked domain", "evil-site.example", false},
		{"case insensitive", "Google.Com", true},
		{"case insensitive subdomain", "Docs.Google.COM", true},
		{"partial name not blocked", "notgoogle.com", false},
		{"empty string", "", false},
		{"tld only", "com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDomainBlocked(tt.domain)
			if got != tt.blocked {
				t.Errorf("isDomainBlocked(%q) = %v, want %v", tt.domain, got, tt.blocked)
			}
		})
	}
}

func TestBlockedBaseDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"exact match", "google.com", "google.com"},
		{"subdomain", "docs.google.com", "google.com"},
		{"not blocked", "evil-site.example", ""},
		{"case insensitive", "Facebook.COM", "facebook.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := blockedBaseDomain(tt.domain)
			if got != tt.want {
				t.Errorf("blockedBaseDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestLoadBlockedDomains(t *testing.T) {
	data := `# comment
google.com
  youtube.com

# another comment

facebook.com
`
	m := loadBlockedDomains(data)
	if len(m) != 3 {
		t.Fatalf("expected 3 domains, got %d", len(m))
	}
	for _, d := range []string{"google.com", "youtube.com", "facebook.com"} {
		if !m[d] {
			t.Errorf("expected %q in blocklist", d)
		}
	}
}
