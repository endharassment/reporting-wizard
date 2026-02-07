package server

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiterConfig holds configuration for rate limiting.
type RateLimiterConfig struct {
	// Per-IP limits for general requests.
	GeneralRequestsPerMin int
	// Per-IP limits for report submission endpoints.
	ReportRequestsPerMin int
	// Per-user report submission limits.
	UserReportsPerHour int
	UserReportsPerDay  int
	// CleanupInterval is how often stale buckets are purged.
	CleanupInterval time.Duration
}

// DefaultRateLimiterConfig returns sensible defaults.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		GeneralRequestsPerMin: 60,
		ReportRequestsPerMin:  10,
		UserReportsPerHour:    5,
		UserReportsPerDay:     20,
		CleanupInterval:       5 * time.Minute,
	}
}

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func newTokenBucket(maxTokens float64, refillRate float64) *tokenBucket {
	return &tokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (b *tokenBucket) stale(ttl time.Duration) bool {
	return time.Since(b.lastRefill) > ttl
}

// RateLimiter provides per-IP and per-user rate limiting.
type RateLimiter struct {
	config RateLimiterConfig

	ipBuckets   sync.Map // map[string]*tokenBucket (keyed by IP)
	userBuckets sync.Map // map[string]*userRateState (keyed by userID)

	mu     sync.Mutex
	stopCh chan struct{}
}

// userRateState tracks per-user rate limits using separate hourly and daily
// token buckets.
type userRateState struct {
	hourly *tokenBucket
	daily  *tokenBucket
}

// NewRateLimiter creates a new RateLimiter and starts a background cleanup
// goroutine. Call Stop() to release resources.
func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		config: config,
		stopCh: make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop halts the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

func (rl *RateLimiter) cleanup() {
	interval := rl.config.CleanupInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			ttl := 10 * time.Minute
			rl.ipBuckets.Range(func(key, value any) bool {
				if b, ok := value.(*tokenBucket); ok && b.stale(ttl) {
					rl.ipBuckets.Delete(key)
				}
				return true
			})
			rl.userBuckets.Range(func(key, value any) bool {
				if s, ok := value.(*userRateState); ok && s.hourly.stale(ttl) && s.daily.stale(ttl) {
					rl.userBuckets.Delete(key)
				}
				return true
			})
		}
	}
}

// AllowIP checks whether a request from the given IP is allowed under the
// general per-IP rate limit. Returns true if allowed.
func (rl *RateLimiter) AllowIP(ip string, perMinLimit int) bool {
	rate := float64(perMinLimit) / 60.0
	maxTokens := float64(perMinLimit)

	val, _ := rl.ipBuckets.LoadOrStore(ip, newTokenBucket(maxTokens, rate))
	bucket := val.(*tokenBucket)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	return bucket.allow()
}

// AllowUserReport checks whether a user is allowed to submit a report under
// per-user hourly and daily limits. Returns true if allowed.
func (rl *RateLimiter) AllowUserReport(userID string) bool {
	hourlyRate := float64(rl.config.UserReportsPerHour) / 3600.0
	dailyRate := float64(rl.config.UserReportsPerDay) / 86400.0

	val, _ := rl.userBuckets.LoadOrStore(userID, &userRateState{
		hourly: newTokenBucket(float64(rl.config.UserReportsPerHour), hourlyRate),
		daily:  newTokenBucket(float64(rl.config.UserReportsPerDay), dailyRate),
	})
	state := val.(*userRateState)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if !state.hourly.allow() {
		return false
	}
	if !state.daily.allow() {
		return false
	}
	return true
}

// IPRateLimitMiddleware returns middleware that enforces per-IP rate limits
// on all requests. It returns 429 Too Many Requests when the limit is exceeded.
func IPRateLimitMiddleware(rl *RateLimiter, perMinLimit int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			if !rl.AllowIP(ip, perMinLimit) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReportRateLimitMiddleware returns middleware that enforces stricter per-IP
// rate limits on report submission endpoints.
func ReportRateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			if !rl.AllowIP(ip, rl.config.ReportRequestsPerMin) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractIP returns the client IP from the request, preferring
// X-Forwarded-For if behind a trusted reverse proxy. In production,
// this should be configured to only trust known proxy IPs.
func extractIP(r *http.Request) string {
	// In production behind a reverse proxy, use the first entry in
	// X-Forwarded-For from a trusted proxy. For now, fall back to RemoteAddr.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the leftmost (client) IP. In production, validate this
		// against trusted proxy list.
		for i := range xff {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
