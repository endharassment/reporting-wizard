package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName = "session_id"
	sessionDuration   = 7 * 24 * time.Hour
)

// SessionMiddleware reads the session cookie, validates the session, and
// injects the user into the request context.
func (s *Server) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}

		sess, err := s.store.GetSession(r.Context(), c.Value)
		if err != nil {
			// Invalid or expired session; clear cookie.
			http.SetCookie(w, &http.Cookie{
				Name:   sessionCookieName,
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			next.ServeHTTP(w, r)
			return
		}

		if time.Now().UTC().After(sess.ExpiresAt) {
			_ = s.store.DeleteSession(r.Context(), sess.ID)
			http.SetCookie(w, &http.Cookie{
				Name:   sessionCookieName,
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			next.ServeHTTP(w, r)
			return
		}

		user, err := s.store.GetUser(r.Context(), sess.UserID)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		r = r.WithContext(withUser(r.Context(), user))
		next.ServeHTTP(w, r)
	})
}

// RequireAuth redirects unauthenticated users to the login page.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromContext(r.Context()) == nil {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin returns 403 if the user is not an admin.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil || !user.IsAdmin {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HandleLogin renders the login page.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login.html", nil)
}

// HandleLogout handles POST /auth/logout.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err == nil && c.Value != "" {
		_ = s.store.DeleteSession(r.Context(), c.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// --- OAuth: Google ---

func (s *Server) googleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.config.GoogleClientID,
		ClientSecret: s.config.GoogleSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: s.config.BaseURL + "/auth/google/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}
}

// HandleGoogleLogin redirects to Google OAuth.
func (s *Server) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if s.config.GoogleClientID == "" {
		http.Error(w, "Google login not configured", http.StatusNotImplemented)
		return
	}
	state := generateRandomHex(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(s.config.BaseURL, "https"),
	})
	url := s.googleOAuthConfig().AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleGoogleCallback handles the Google OAuth callback.
func (s *Server) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if err := s.validateOAuthState(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := s.googleOAuthConfig()
	token, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("ERROR: google oauth exchange: %v", err)
		http.Error(w, "OAuth error", http.StatusBadRequest)
		return
	}

	client := cfg.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		log.Printf("ERROR: google userinfo: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var info struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		log.Printf("ERROR: decode google userinfo: %v", err)
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	user, err := s.getOrCreateUser(r.Context(), info.Email, info.Name)
	if err != nil {
		log.Printf("ERROR: get or create user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := s.createSession(w, r, user.ID); err != nil {
		log.Printf("ERROR: create session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// --- OAuth: GitHub ---

func (s *Server) githubOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.config.GitHubClientID,
		ClientSecret: s.config.GitHubSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
		RedirectURL: s.config.BaseURL + "/auth/github/callback",
		Scopes:      []string{"user:email"},
	}
}

// HandleGitHubLogin redirects to GitHub OAuth.
func (s *Server) HandleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	if s.config.GitHubClientID == "" {
		http.Error(w, "GitHub login not configured", http.StatusNotImplemented)
		return
	}
	state := generateRandomHex(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(s.config.BaseURL, "https"),
	})
	url := s.githubOAuthConfig().AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleGitHubCallback handles the GitHub OAuth callback.
func (s *Server) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if err := s.validateOAuthState(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := s.githubOAuthConfig()
	token, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("ERROR: github oauth exchange: %v", err)
		http.Error(w, "OAuth error", http.StatusBadRequest)
		return
	}

	client := cfg.Client(r.Context(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		log.Printf("ERROR: github user API: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var ghUser struct {
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		log.Printf("ERROR: decode github user: %v", err)
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	// GitHub may not return email in user API; fetch from emails API.
	email := ghUser.Email
	if email == "" {
		email, err = s.fetchGitHubEmail(r.Context(), client)
		if err != nil {
			log.Printf("ERROR: fetch github email: %v", err)
			http.Error(w, "Could not retrieve email from GitHub", http.StatusInternalServerError)
			return
		}
	}

	name := ghUser.Name
	if name == "" {
		name = ghUser.Login
	}

	user, err := s.getOrCreateUser(r.Context(), email, name)
	if err != nil {
		log.Printf("ERROR: get or create user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := s.createSession(w, r, user.ID); err != nil {
		log.Printf("ERROR: create session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) fetchGitHubEmail(ctx context.Context, client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}
	if len(emails) > 0 {
		return emails[0].Email, nil
	}
	return "", fmt.Errorf("no email found in GitHub account")
}

// --- Helpers ---

func (s *Server) validateOAuthState(r *http.Request) error {
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value == "" {
		return fmt.Errorf("missing OAuth state cookie")
	}
	stateParam := r.URL.Query().Get("state")
	if stateParam != stateCookie.Value {
		return fmt.Errorf("OAuth state mismatch")
	}
	return nil
}

func (s *Server) getOrCreateUser(ctx context.Context, email, name string) (*model.User, error) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err == nil {
		return user, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	user = &model.User{
		ID:        uuid.New().String(),
		Email:     email,
		Name:      name,
		IsAdmin:   false,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, userID string) error {
	sessID := uuid.New().String()
	now := time.Now().UTC()

	sess := &model.Session{
		ID:        sessID,
		UserID:    userID,
		ExpiresAt: now.Add(sessionDuration),
		CreatedAt: now,
	}

	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessID,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   strings.HasPrefix(s.config.BaseURL, "https"),
	})

	return nil
}
