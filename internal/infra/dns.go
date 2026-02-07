package infra

import (
	"context"
	"net"

	"github.com/endharassment/reporting-wizard/internal/model"
)

// DNSResolver abstracts DNS lookups for testing.
type DNSResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// netResolver wraps net.Resolver to implement DNSResolver.
type netResolver struct {
	r *net.Resolver
}

func (n *netResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return n.r.LookupIP(ctx, network, host)
}

// NewDNSResolver returns a DNSResolver backed by the system resolver.
func NewDNSResolver() DNSResolver {
	return &netResolver{r: net.DefaultResolver}
}

// LookupDomain resolves A and AAAA records for a domain, returning partially
// filled InfraResults with IP and RecordType set.
func LookupDomain(ctx context.Context, resolver DNSResolver, domain string) ([]model.InfraResult, error) {
	var results []model.InfraResult

	ip4s, err := resolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		// If no A records exist, that's not necessarily fatal.
		if !isNoSuchHost(err) {
			return nil, err
		}
	}
	for _, ip := range ip4s {
		results = append(results, model.InfraResult{
			IP:         ip.String(),
			RecordType: "A",
		})
	}

	ip6s, err := resolver.LookupIP(ctx, "ip6", domain)
	if err != nil {
		if !isNoSuchHost(err) {
			return nil, err
		}
	}
	for _, ip := range ip6s {
		results = append(results, model.InfraResult{
			IP:         ip.String(),
			RecordType: "AAAA",
		})
	}

	if len(results) == 0 {
		return nil, &net.DNSError{
			Err:        "no A or AAAA records found",
			Name:       domain,
			IsNotFound: true,
		}
	}

	return results, nil
}

func isNoSuchHost(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && dnsErr.IsNotFound
}
