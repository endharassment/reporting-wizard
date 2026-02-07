package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenBucketAllow(t *testing.T) {
	tests := []struct {
		name      string
		max       float64
		rate      float64
		calls     int
		wantAllow int
	}{
		{
			name:      "allows up to max tokens",
			max:       3,
			rate:      1,
			calls:     5,
			wantAllow: 3,
		},
		{
			name:      "single token",
			max:       1,
			rate:      1,
			calls:     2,
			wantAllow: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTokenBucket(tt.max, tt.rate)
			allowed := 0
			for range tt.calls {
				if b.allow() {
					allowed++
				}
			}
			if allowed != tt.wantAllow {
				t.Errorf("got %d allowed, want %d", allowed, tt.wantAllow)
			}
		})
	}
}

func TestTokenBucketRefill(t *testing.T) {
	b := newTokenBucket(2, 1000) // 1000 tokens/sec refill
	// Drain the bucket.
	b.allow()
	b.allow()
	if b.allow() {
		t.Fatal("expected bucket to be empty")
	}

	// Wait for refill.
	time.Sleep(10 * time.Millisecond)
	if !b.allow() {
		t.Error("expected bucket to have refilled after sleep")
	}
}

func TestRateLimiterAllowIP(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.CleanupInterval = time.Hour // don't interfere with test
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	ip := "192.0.2.1"
	limit := 5
	allowed := 0
	for range 10 {
		if rl.AllowIP(ip, limit) {
			allowed++
		}
	}
	if allowed != limit {
		t.Errorf("got %d allowed, want %d", allowed, limit)
	}

	// Different IP should have its own bucket.
	if !rl.AllowIP("192.0.2.2", limit) {
		t.Error("different IP should be allowed")
	}
}

func TestRateLimiterAllowUserReport(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.UserReportsPerHour = 3
	cfg.UserReportsPerDay = 5
	cfg.CleanupInterval = time.Hour
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	userID := "user-1"
	allowed := 0
	for range 10 {
		if rl.AllowUserReport(userID) {
			allowed++
		}
	}
	// Should be limited by the hourly cap (3).
	if allowed != cfg.UserReportsPerHour {
		t.Errorf("got %d allowed, want %d (hourly limit)", allowed, cfg.UserReportsPerHour)
	}
}

func TestIPRateLimitMiddleware(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.CleanupInterval = time.Hour
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := IPRateLimitMiddleware(rl, 3)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	okCount := 0
	limitedCount := 0
	for range 10 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			okCount++
		} else if rec.Code == http.StatusTooManyRequests {
			limitedCount++
		}
	}
	if okCount != 3 {
		t.Errorf("got %d OK responses, want 3", okCount)
	}
	if limitedCount != 7 {
		t.Errorf("got %d rate-limited responses, want 7", limitedCount)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "remote addr with port",
			remoteAddr: "192.0.2.1:12345",
			want:       "192.0.2.1",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "192.0.2.1",
			want:       "192.0.2.1",
		},
		{
			name:       "xff single",
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "xff multiple",
			remoteAddr: "127.0.0.1:80",
			xff:        "203.0.113.50, 70.41.3.18, 150.172.238.178",
			want:       "203.0.113.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			got := extractIP(req)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
