package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"
)

// RequestIDFromContext returns the request ID from the context, if present.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return id
	}
	return ""
}

// --- Request ID Middleware ---

var requestCounter atomic.Uint64

// RequestIDMiddleware assigns a unique request ID to each request and adds it
// to the response headers and request context.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			seq := requestCounter.Add(1)
			id = fmt.Sprintf("%d-%d", time.Now().UnixMilli(), seq)
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Logging Middleware ---

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.written += int64(n)
	return n, err
}

// LoggingMiddleware logs each request with structured fields including method,
// path, status code, duration, and request ID.
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rw, r)
			duration := time.Since(start)

			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.statusCode,
				"duration_ms", duration.Milliseconds(),
				"bytes", rw.written,
				"remote_addr", r.RemoteAddr,
				"request_id", RequestIDFromContext(r.Context()),
			)
		})
	}
}

// --- Recovery Middleware ---

// RecoveryMiddleware recovers from panics in downstream handlers, logs the
// stack trace, and returns a 500 Internal Server Error.
func RecoveryMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					stack := debug.Stack()
					logger.Error("panic recovered",
						"error", fmt.Sprintf("%v", rec),
						"stack", string(stack),
						"method", r.Method,
						"path", r.URL.Path,
						"request_id", RequestIDFromContext(r.Context()),
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// --- Security Headers Middleware ---

// SecurityHeadersMiddleware sets security-related HTTP headers on all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// --- CSRF Middleware ---

const (
	csrfCookieName = "_csrf"
	csrfFieldName  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfTokenBytes = 32
)

// CSRFMiddleware provides CSRF protection using the double-submit cookie
// pattern with HMAC verification.
func CSRFMiddleware(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				token, err := generateCSRFToken(secret)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					Secure:   true,
				})
				ctx := withCSRFToken(r.Context(), token)
				next.ServeHTTP(w, r.WithContext(ctx))

			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				cookie, err := r.Cookie(csrfCookieName)
				if err != nil {
					http.Error(w, "Forbidden: missing CSRF cookie", http.StatusForbidden)
					return
				}

				submitted := r.FormValue(csrfFieldName)
				if submitted == "" {
					submitted = r.Header.Get(csrfHeaderName)
				}
				if submitted == "" {
					http.Error(w, "Forbidden: missing CSRF token", http.StatusForbidden)
					return
				}

				if !validateCSRFToken(secret, cookie.Value, submitted) {
					http.Error(w, "Forbidden: invalid CSRF token", http.StatusForbidden)
					return
				}

				token, err := generateCSRFToken(secret)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					Secure:   true,
				})
				ctx := withCSRFToken(r.Context(), token)
				next.ServeHTTP(w, r.WithContext(ctx))

			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

// CSRFTokenFromContext returns the CSRF token from the context, if present.
func CSRFTokenFromContext(ctx context.Context) string {
	t, _ := ctx.Value(ctxKeyCSRFToken).(string)
	return t
}

// generateCSRFToken creates a random token and signs it with HMAC.
func generateCSRFToken(secret []byte) (string, error) {
	randomBytes := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generating CSRF random bytes: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)
	mac := hmac.New(sha256.New, secret)
	mac.Write(randomBytes)
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return encoded + "." + sig, nil
}

// validateCSRFToken checks that two CSRF tokens are valid and equal.
func validateCSRFToken(secret []byte, cookieToken, submittedToken string) bool {
	cookieParts := strings.SplitN(cookieToken, ".", 2)
	submittedParts := strings.SplitN(submittedToken, ".", 2)
	if len(cookieParts) != 2 || len(submittedParts) != 2 {
		return false
	}

	cookieRandom, err := base64.RawURLEncoding.DecodeString(cookieParts[0])
	if err != nil {
		return false
	}
	cookieSig, err := base64.RawURLEncoding.DecodeString(cookieParts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(cookieRandom)
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(cookieSig, expectedSig) {
		return false
	}

	return hmac.Equal([]byte(cookieToken), []byte(submittedToken))
}

// generateRandomHex creates a random hex-encoded string (for OAuth state, etc.)
func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
