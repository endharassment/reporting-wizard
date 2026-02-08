package infra

import (
	"context"
	"sync"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	"golang.org/x/sync/errgroup"
)

// MaxConcurrency is the default bound on parallel lookups.
const MaxConcurrency = 8

// Per-operation timeouts recommended by the security review.
const (
	dnsTimeout  = 10 * time.Second
	asnTimeout  = 10 * time.Second
	rdapTimeout = 15 * time.Second
	bgpTimeout  = 10 * time.Second
)

// Discovery orchestrates the full infrastructure discovery pipeline.
type Discovery struct {
	DNS  DNSResolver
	ASN  ASNClient
	RDAP RDAPClient
	BGP  BGPClient

	// In-memory caches keyed by domain/IP/ASN with TTL.
	// Nil caches are safe (no-op) so tests can omit them.
	dnsCache  *ttlCache[string, []model.InfraResult]
	asnCache  *ttlCache[string, *ASNInfo]
	rdapCache *ttlCache[string, string]
	bgpCache  *ttlCache[int, []int]
}

// NewDiscovery returns a Discovery with production clients and caching.
func NewDiscovery() *Discovery {
	return &Discovery{
		DNS:       NewDNSResolver(),
		ASN:       NewASNClient(),
		RDAP:      NewRDAPClient(),
		BGP:       NewBGPClient(),
		dnsCache:  newTTLCache[string, []model.InfraResult](DefaultCacheTTL),
		asnCache:  newTTLCache[string, *ASNInfo](DefaultCacheTTL),
		rdapCache: newTTLCache[string, string](DefaultCacheTTL),
		bgpCache:  newTTLCache[int, []int](DefaultCacheTTL),
	}
}

// DiscoveryResult holds the output of a full discovery pipeline run.
type DiscoveryResult struct {
	// InfraResults contains per-IP infrastructure details.
	InfraResults []model.InfraResult
	// UpstreamGraph maps each ASN to its direct upstream ASNs, recursively
	// walked until Tier 1 providers (no upstreams) are reached.
	UpstreamGraph map[int][]int
}

// Run executes the full discovery pipeline for a domain:
//  1. DNS lookup to get IPs
//  2. For each IP: ASN lookup, Cloudflare check, RDAP abuse contact
//  3. For each unique ASN: BGP upstream lookup
//  4. Recursively walk upstream chain until Tier 1 / cycle
//  5. Returns *DiscoveryResult with InfraResults and full UpstreamGraph
func (d *Discovery) Run(ctx context.Context, domain string) (*DiscoveryResult, error) {
	// Step 1: DNS resolution.
	results, err := d.lookupDNSCached(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Step 2: Parallel ASN + RDAP lookups per IP.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(MaxConcurrency)

	var mu sync.Mutex

	for i := range results {
		i := i
		ip := results[i].IP

		// ASN lookup.
		g.Go(func() error {
			info, err := d.lookupASNCached(gctx, ip)
			if err != nil {
				return err
			}
			mu.Lock()
			results[i].ASN = info.ASN
			results[i].ASNName = info.ASNName
			results[i].BGPPrefix = info.BGPPrefix
			results[i].Country = info.Country
			mu.Unlock()
			return nil
		})

		// RDAP abuse contact lookup.
		g.Go(func() error {
			contact, err := d.lookupRDAPCached(gctx, ip)
			if err != nil {
				// RDAP failures are non-fatal; we still have other data.
				return nil
			}
			mu.Lock()
			results[i].AbuseContact = contact
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Mark Cloudflare.
	MarkCloudflare(results)

	// Step 3: Collect unique ASNs and look up BGP upstreams.
	asnSet := make(map[int]bool)
	for _, r := range results {
		if r.ASN != 0 {
			asnSet[r.ASN] = true
		}
	}

	upstreamMap := make(map[int][]int)
	var upMu sync.Mutex

	g2, gctx2 := errgroup.WithContext(ctx)
	g2.SetLimit(MaxConcurrency)

	for asn := range asnSet {
		asn := asn
		g2.Go(func() error {
			upstreams, err := d.lookupBGPCached(gctx2, asn)
			if err != nil {
				// BGP failures are non-fatal.
				return nil
			}
			upMu.Lock()
			upstreamMap[asn] = upstreams
			upMu.Unlock()
			return nil
		})
	}

	if err := g2.Wait(); err != nil {
		return nil, err
	}

	// Attach upstream ASNs to results.
	for i := range results {
		if ups, ok := upstreamMap[results[i].ASN]; ok {
			results[i].UpstreamASNs = ups
		}
	}

	// Step 4: Recursively walk the upstream chain. Seed with all ASNs
	// discovered so far (hosting ASNs + their direct upstreams).
	var seedASNs []int
	for asn := range asnSet {
		seedASNs = append(seedASNs, asn)
	}
	for _, ups := range upstreamMap {
		seedASNs = append(seedASNs, ups...)
	}

	upstreamGraph, err := d.walkUpstreamChainCached(ctx, seedASNs)
	if err != nil {
		// Non-fatal: we still have single-level upstream data.
		upstreamGraph = upstreamMap
	}
	// Merge in the hosting ASNs' upstreams (already known from step 3).
	for asn, ups := range upstreamMap {
		if _, ok := upstreamGraph[asn]; !ok {
			upstreamGraph[asn] = ups
		}
	}

	return &DiscoveryResult{
		InfraResults:  results,
		UpstreamGraph: upstreamGraph,
	}, nil
}

// --- Cached lookup helpers ---

func (d *Discovery) lookupDNSCached(ctx context.Context, domain string) ([]model.InfraResult, error) {
	if cached, ok := d.dnsCache.Get(domain); ok {
		// Return a copy so callers can mutate without corrupting the cache.
		out := make([]model.InfraResult, len(cached))
		copy(out, cached)
		return out, nil
	}

	tctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	results, err := LookupDomain(tctx, d.DNS, domain)
	if err != nil {
		return nil, err
	}
	d.dnsCache.Set(domain, results)
	return results, nil
}

func (d *Discovery) lookupASNCached(ctx context.Context, ip string) (*ASNInfo, error) {
	if cached, ok := d.asnCache.Get(ip); ok {
		return cached, nil
	}

	tctx, cancel := context.WithTimeout(ctx, asnTimeout)
	defer cancel()

	info, err := LookupASN(tctx, d.ASN, ip)
	if err != nil {
		return nil, err
	}
	d.asnCache.Set(ip, info)
	return info, nil
}

func (d *Discovery) lookupRDAPCached(ctx context.Context, ip string) (string, error) {
	if cached, ok := d.rdapCache.Get(ip); ok {
		return cached, nil
	}

	tctx, cancel := context.WithTimeout(ctx, rdapTimeout)
	defer cancel()

	contact, err := LookupAbuseContact(tctx, d.RDAP, ip)
	if err != nil {
		return "", err
	}
	d.rdapCache.Set(ip, contact)
	return contact, nil
}

func (d *Discovery) lookupBGPCached(ctx context.Context, asn int) ([]int, error) {
	if cached, ok := d.bgpCache.Get(asn); ok {
		return cached, nil
	}

	tctx, cancel := context.WithTimeout(ctx, bgpTimeout)
	defer cancel()

	upstreams, err := d.BGP.LookupUpstreams(tctx, asn)
	if err != nil {
		return nil, err
	}
	d.bgpCache.Set(asn, upstreams)
	return upstreams, nil
}

// walkUpstreamChainCached is like WalkUpstreamChain but uses the BGP cache.
func (d *Discovery) walkUpstreamChainCached(ctx context.Context, seedASNs []int) (map[int][]int, error) {
	graph := make(map[int][]int)
	visited := make(map[int]bool)

	queue := make([]int, 0, len(seedASNs))
	for _, asn := range seedASNs {
		if asn != 0 && !visited[asn] {
			visited[asn] = true
			queue = append(queue, asn)
		}
	}

	for len(queue) > 0 {
		batch := queue
		queue = nil

		batchResults := make(map[int][]int)
		var mu sync.Mutex

		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(MaxConcurrency)

		for _, asn := range batch {
			asn := asn
			if _, ok := graph[asn]; ok {
				continue
			}
			g.Go(func() error {
				upstreams, err := d.lookupBGPCached(gctx, asn)
				if err != nil {
					mu.Lock()
					batchResults[asn] = nil
					mu.Unlock()
					return nil
				}
				mu.Lock()
				batchResults[asn] = upstreams
				mu.Unlock()
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return graph, err
		}

		for asn, upstreams := range batchResults {
			graph[asn] = upstreams
			for _, u := range upstreams {
				if u != 0 && !visited[u] {
					visited[u] = true
					queue = append(queue, u)
				}
			}
		}
	}

	return graph, nil
}

// WalkUpstreamChain performs a BFS over BGP upstream relationships starting
// from seedASNs. It returns a map of every ASN visited to its direct
// upstreams. The walk terminates when an ASN has no upstreams (Tier 1) or
// has already been visited (cycle guard).
//
// This is the uncached version used by tests. Production code uses
// walkUpstreamChainCached via Discovery.Run.
func WalkUpstreamChain(ctx context.Context, bgp BGPClient, seedASNs []int) (map[int][]int, error) {
	graph := make(map[int][]int)
	visited := make(map[int]bool)

	// Queue of ASNs to process.
	queue := make([]int, 0, len(seedASNs))
	for _, asn := range seedASNs {
		if asn != 0 && !visited[asn] {
			visited[asn] = true
			queue = append(queue, asn)
		}
	}

	// BFS in rounds. Each round processes the current queue in parallel,
	// then enqueues newly discovered ASNs.
	for len(queue) > 0 {
		batch := queue
		queue = nil

		batchResults := make(map[int][]int)
		var mu sync.Mutex

		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(MaxConcurrency)

		for _, asn := range batch {
			asn := asn
			if _, ok := graph[asn]; ok {
				continue // already resolved
			}
			g.Go(func() error {
				tctx, cancel := context.WithTimeout(gctx, bgpTimeout)
				defer cancel()

				upstreams, err := bgp.LookupUpstreams(tctx, asn)
				if err != nil {
					// BGP failures are non-fatal; record empty upstreams.
					mu.Lock()
					batchResults[asn] = nil
					mu.Unlock()
					return nil
				}
				mu.Lock()
				batchResults[asn] = upstreams
				mu.Unlock()
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return graph, err
		}

		for asn, upstreams := range batchResults {
			graph[asn] = upstreams
			for _, u := range upstreams {
				if u != 0 && !visited[u] {
					visited[u] = true
					queue = append(queue, u)
				}
			}
		}
	}

	return graph, nil
}
