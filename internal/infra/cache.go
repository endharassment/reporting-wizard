package infra

import (
	"sync"
	"time"
)

// DefaultCacheTTL is the default time-to-live for cached infra lookups.
// Most reports target the same small set of domains, so caching prevents
// amplification against external services (DNS, RDAP, Team Cymru, bgp.tools).
const DefaultCacheTTL = 1 * time.Hour

type cacheEntry[V any] struct {
	value     V
	expiresAt time.Time
}

// ttlCache is a simple in-memory cache with per-entry expiration.
// All methods are safe for concurrent use and nil-receiver safe
// (a nil cache is a no-op, which lets Discovery work without caching
// when constructed directly in tests).
type ttlCache[K comparable, V any] struct {
	mu      sync.RWMutex
	entries map[K]cacheEntry[V]
	ttl     time.Duration
}

func newTTLCache[K comparable, V any](ttl time.Duration) *ttlCache[K, V] {
	return &ttlCache[K, V]{
		entries: make(map[K]cacheEntry[V]),
		ttl:     ttl,
	}
}

// Get returns the cached value and true if the key exists and has not expired.
// On a nil receiver, it always returns the zero value and false.
func (c *ttlCache[K, V]) Get(key K) (V, bool) {
	if c == nil {
		var zero V
		return zero, false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		var zero V
		return zero, false
	}
	return entry.value, true
}

// Set stores a value with the cache's default TTL.
// On a nil receiver, it is a no-op.
func (c *ttlCache[K, V]) Set(key K, value V) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries[key] = cacheEntry[V]{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Len returns the number of entries (including expired) in the cache.
func (c *ttlCache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
