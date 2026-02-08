package server

import (
	_ "embed"
	"strings"
)

//go:embed blocked_domains.txt
var blockedDomainsData string

var blockedDomains map[string]bool

func init() {
	blockedDomains = loadBlockedDomains(blockedDomainsData)
}

func loadBlockedDomains(data string) map[string]bool {
	m := make(map[string]bool)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = true
	}
	return m
}

// isDomainBlocked returns true if the domain (or any parent domain) is in the
// blocklist. For example, docs.google.com is blocked because google.com is
// in the list.
func isDomainBlocked(domain string) bool {
	domain = strings.ToLower(domain)
	if blockedDomains[domain] {
		return true
	}
	// Progressively strip leading labels.
	for {
		idx := strings.Index(domain, ".")
		if idx < 0 {
			return false
		}
		domain = domain[idx+1:]
		if blockedDomains[domain] {
			return true
		}
	}
}

// blockedBaseDomain returns the base domain from the blocklist that matches,
// or empty string if not blocked.
func blockedBaseDomain(domain string) string {
	domain = strings.ToLower(domain)
	if blockedDomains[domain] {
		return domain
	}
	for {
		idx := strings.Index(domain, ".")
		if idx < 0 {
			return ""
		}
		domain = domain[idx+1:]
		if blockedDomains[domain] {
			return domain
		}
	}
}
