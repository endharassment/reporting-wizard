package boilerplate

import "strings"

// DomainInfo holds contextual information about a known problem domain.
type DomainInfo struct {
	Domain      string   // primary exact domain match
	Aliases     []string // additional exact domain matches
	Patterns    []string // wildcard suffix patterns, e.g. "*.kiwifarms.*"
	DisplayName string   // human-friendly name
	Summary     string   // 1-2 sentence description for abuse reports
	Context     string   // longer paragraph with history
	KnownASNs   []int    // ASNs historically associated with this domain
}

// DB holds the collection of known domain entries.
type DB struct {
	domains []DomainInfo
}

// NewDB creates a DB populated with built-in domain entries.
func NewDB() *DB {
	return &DB{
		domains: builtinDomains(),
	}
}

// Lookup finds domain info for the given domain.
// It checks exact matches first (Domain and Aliases), then wildcard Patterns.
// Returns nil if no match is found. Matching is case-insensitive.
func (db *DB) Lookup(domain string) *DomainInfo {
	domain = strings.ToLower(domain)

	// Exact match first.
	for i := range db.domains {
		if strings.ToLower(db.domains[i].Domain) == domain {
			return &db.domains[i]
		}
		for _, alias := range db.domains[i].Aliases {
			if strings.ToLower(alias) == domain {
				return &db.domains[i]
			}
		}
	}

	// Wildcard pattern match.
	for i := range db.domains {
		for _, pattern := range db.domains[i].Patterns {
			if matchWildcard(strings.ToLower(pattern), domain) {
				return &db.domains[i]
			}
		}
	}

	return nil
}

// matchWildcard matches a pattern like "*.kiwifarms.*" against a domain.
// Supported wildcards:
//   - Leading "*." matches any subdomain prefix (including nested)
//   - Trailing ".*" matches any TLD suffix
func matchWildcard(pattern, domain string) bool {
	// Handle leading "*."
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:] // e.g., "kiwifarms.*"
		// Check if suffix also has trailing wildcard
		if strings.HasSuffix(suffix, ".*") {
			// Pattern like "*.kiwifarms.*" -- domain must contain ".kiwifarms." or start with "kiwifarms."
			core := suffix[:len(suffix)-2] // e.g., "kiwifarms"
			return strings.Contains(domain, "."+core+".") ||
				strings.HasPrefix(domain, core+".") ||
				domain == core
		}
		// Pattern like "*.example.com" -- domain must end with ".example.com" or be exactly "example.com"
		return strings.HasSuffix(domain, "."+suffix) || domain == suffix
	}

	// Handle trailing ".*" only
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2] // e.g., "kiwifarms"
		return strings.HasPrefix(domain, prefix+".") || domain == prefix
	}

	// No wildcards, exact match
	return pattern == domain
}

func builtinDomains() []DomainInfo {
	return []DomainInfo{
		{
			Domain:      "kiwifarms.net",
			Aliases:     []string{"kiwifarms.st", "kiwifarms.ru", "kiwifarms.is", "kiwifarms.top", "kiwifarms.cc"},
			Patterns:    []string{"*.kiwifarms.*"},
			DisplayName: "Kiwi Farms",
			Summary:     "Kiwi Farms is a well-documented harassment and doxxing forum that has been linked to multiple suicides and real-world violence against its targets.",
			Context: "Kiwi Farms (formerly known as CWCki Forums) is a website primarily dedicated to " +
				"the targeted harassment, doxxing, and stalking of individuals. The site has been " +
				"linked to at least three suicides and numerous cases of real-world harassment campaigns. " +
				"Multiple infrastructure providers including Cloudflare (September 2022), DDoS-Guard, " +
				"and various hosting providers have previously terminated service to this domain. " +
				"The site frequently migrates between TLDs and hosting providers to evade enforcement. " +
				"We encourage you to review this content under your acceptable use policy.",
			KnownASNs: []int{},
		},
	}
}
