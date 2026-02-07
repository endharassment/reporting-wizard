package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestIDMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		existingID string
		wantCustom bool
	}{
		{
			name:       "generates ID when none provided",
			existingID: "",
			wantCustom: false,
		},
		{
			name:       "preserves existing ID",
			existingID: "custom-id-123",
			wantCustom: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctxID string
			handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctxID = RequestIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.existingID != "" {
				req.Header.Set("X-Request-ID", tt.existingID)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			respID := rec.Header().Get("X-Request-ID")
			if respID == "" {
				t.Error("expected X-Request-ID header in response")
			}
			if tt.wantCustom && respID != tt.existingID {
				t.Errorf("got %q, want %q", respID, tt.existingID)
			}
			if ctxID != respID {
				t.Errorf("context ID %q != response header ID %q", ctxID, respID)
			}
		})
	}
}

func TestLoggingMiddleware(t *testing.T) {
	logger := slog.Default()
	handler := LoggingMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	logger := slog.Default()
	handler := RecoveryMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()

	// Should not panic.
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"X-XSS-Protection":       "0",
	}

	for header, expected := range expectedHeaders {
		got := rec.Header().Get(header)
		if got != expected {
			t.Errorf("header %s = %q, want %q", header, got, expected)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self': %s", csp)
	}

	pp := rec.Header().Get("Permissions-Policy")
	if pp == "" {
		t.Error("expected Permissions-Policy header")
	}
}

func TestCSRFMiddleware(t *testing.T) {
	secret := []byte("test-secret-key-for-csrf-tokens!")

	t.Run("GET sets cookie and context token", func(t *testing.T) {
		var ctxToken string
		handler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctxToken = CSRFTokenFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/form", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
		}
		if ctxToken == "" {
			t.Error("expected CSRF token in context")
		}

		cookies := rec.Result().Cookies()
		var found bool
		for _, c := range cookies {
			if c.Name == csrfCookieName {
				found = true
				if c.Value != ctxToken {
					t.Errorf("cookie value %q != context token %q", c.Value, ctxToken)
				}
			}
		}
		if !found {
			t.Error("expected CSRF cookie to be set")
		}
	})

	t.Run("POST without cookie returns 403", func(t *testing.T) {
		handler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/submit", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("got status %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("POST with valid token succeeds", func(t *testing.T) {
		// First, get a token via GET.
		var token string
		getHandler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		getReq := httptest.NewRequest(http.MethodGet, "/form", nil)
		getRec := httptest.NewRecorder()
		getHandler.ServeHTTP(getRec, getReq)

		// Now POST with the token.
		postHandler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		form := url.Values{}
		form.Set(csrfFieldName, token)
		postReq := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
		postRec := httptest.NewRecorder()
		postHandler.ServeHTTP(postRec, postReq)

		if postRec.Code != http.StatusOK {
			t.Errorf("got status %d, want %d", postRec.Code, http.StatusOK)
		}
	})

	t.Run("POST with mismatched token returns 403", func(t *testing.T) {
		// Get a valid token.
		var token string
		getHandler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
		getReq := httptest.NewRequest(http.MethodGet, "/form", nil)
		getRec := httptest.NewRecorder()
		getHandler.ServeHTTP(getRec, getReq)

		// Get a different token.
		var token2 string
		getReq2 := httptest.NewRequest(http.MethodGet, "/form", nil)
		getRec2 := httptest.NewRecorder()
		getHandler2 := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token2 = CSRFTokenFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
		getHandler2.ServeHTTP(getRec2, getReq2)

		// POST with cookie from first token but form value from second.
		postHandler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		form := url.Values{}
		form.Set(csrfFieldName, token2)
		postReq := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
		postRec := httptest.NewRecorder()
		postHandler.ServeHTTP(postRec, postReq)

		if postRec.Code != http.StatusForbidden {
			t.Errorf("got status %d, want %d", postRec.Code, http.StatusForbidden)
		}
	})

	t.Run("POST with header token succeeds", func(t *testing.T) {
		var token string
		getHandler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
		getReq := httptest.NewRequest(http.MethodGet, "/form", nil)
		getRec := httptest.NewRecorder()
		getHandler.ServeHTTP(getRec, getReq)

		postHandler := CSRFMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		postReq := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
		postReq.Header.Set(csrfHeaderName, token)
		postReq.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
		postRec := httptest.NewRecorder()
		postHandler.ServeHTTP(postRec, postReq)

		if postRec.Code != http.StatusOK {
			t.Errorf("got status %d, want %d", postRec.Code, http.StatusOK)
		}
	})
}

func TestCSRFTokenGeneration(t *testing.T) {
	secret := []byte("test-secret-key-for-csrf-tokens!")

	token1, err := generateCSRFToken(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token2, err := generateCSRFToken(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token1 == token2 {
		t.Error("expected unique tokens, got identical")
	}

	// Token should contain a dot separator.
	if !strings.Contains(token1, ".") {
		t.Errorf("token missing dot separator: %s", token1)
	}
}

func TestCSRFTokenValidation(t *testing.T) {
	secret := []byte("test-secret-key-for-csrf-tokens!")

	token, err := generateCSRFToken(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name      string
		cookie    string
		submitted string
		want      bool
	}{
		{"matching tokens", token, token, true},
		{"mismatched tokens", token, "wrong.token", false},
		{"empty cookie", "", token, false},
		{"empty submitted", token, "", false},
		{"tampered signature", token, strings.Split(token, ".")[0] + ".tampered", false},
		{"no dot in cookie", "nodot", token, false},
		{"no dot in submitted", token, "nodot", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateCSRFToken(secret, tt.cookie, tt.submitted)
			if got != tt.want {
				t.Errorf("validateCSRFToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
