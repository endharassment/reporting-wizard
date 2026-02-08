package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyRecaptcha(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		handler   http.HandlerFunc
		wantScore float64
		wantErr   bool
	}{
		{
			name:      "empty secret skips verification",
			secret:    "",
			wantScore: 1.0,
		},
		{
			name:   "high score",
			secret: "test-secret",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"score":   0.9,
					"action":  "create_report",
				})
			},
			wantScore: 0.9,
		},
		{
			name:   "low score",
			secret: "test-secret",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"score":   0.1,
					"action":  "create_report",
				})
			},
			wantScore: 0.1,
		},
		{
			name:   "success false returns zero",
			secret: "test-secret",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"score":   0.0,
				})
			},
			wantScore: 0,
		},
		{
			name:   "malformed JSON returns error",
			secret: "test-secret",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("not json"))
			},
			wantErr: true,
		},
		{
			name:   "timeout returns error",
			secret: "test-secret",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(10 * time.Second)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.secret == "" {
				score, err := verifyRecaptcha(context.Background(), "", "token", "1.2.3.4")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if score != tt.wantScore {
					t.Errorf("score = %v, want %v", score, tt.wantScore)
				}
				return
			}

			ts := httptest.NewServer(tt.handler)
			defer ts.Close()

			// Override the verify URL for testing.
			origURL := recaptchaVerifyURL
			defer func() { setRecaptchaVerifyURL(origURL) }()
			setRecaptchaVerifyURL(ts.URL)

			ctx := context.Background()
			if tt.name == "timeout returns error" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}

			score, err := verifyRecaptcha(ctx, tt.secret, "test-token", "1.2.3.4")
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if score != tt.wantScore {
				t.Errorf("score = %v, want %v", score, tt.wantScore)
			}
		})
	}
}

func TestVerifyRecaptchaFormParams(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.FormValue("secret"); got != "my-secret" {
			t.Errorf("secret = %q, want %q", got, "my-secret")
		}
		if got := r.FormValue("response"); got != "my-token" {
			t.Errorf("response = %q, want %q", got, "my-token")
		}
		if got := r.FormValue("remoteip"); got != "5.6.7.8" {
			t.Errorf("remoteip = %q, want %q", got, "5.6.7.8")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"score":   0.7,
		})
	}))
	defer ts.Close()

	origURL := recaptchaVerifyURL
	defer func() { setRecaptchaVerifyURL(origURL) }()
	setRecaptchaVerifyURL(ts.URL)

	score, err := verifyRecaptcha(context.Background(), "my-secret", "my-token", "5.6.7.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score != 0.7 {
		t.Errorf("score = %v, want 0.7", score)
	}
}
