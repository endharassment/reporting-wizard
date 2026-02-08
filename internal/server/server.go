package server

import (
	"context"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"strings"

	"github.com/endharassment/reporting-wizard/internal/admin"
	"github.com/endharassment/reporting-wizard/internal/boilerplate"
	"github.com/endharassment/reporting-wizard/internal/infra"
	"github.com/endharassment/reporting-wizard/internal/report"
	"github.com/endharassment/reporting-wizard/internal/store"
	"github.com/go-chi/chi/v5"
)

// Config holds server configuration.
type Config struct {
	ListenAddr         string
	DBPath             string
	SendGridKey        string
	FromEmail          string
	FromName           string
	BaseURL            string
	GoogleClientID     string
	GoogleSecret       string
	GitHubClientID     string
	GitHubSecret       string
	RecaptchaSiteKey   string
	RecaptchaSecretKey string
	EscalationDays     int
	SessionSecret      string
	IMAPServer         string
	IMAPUsername       string
	IMAPPassword       string
}

// Snapshotter defines the interface for crawling and snapshotting URLs.
type Snapshotter interface {
	// Snapshot fetches a URL and returns its text-only content.
	Snapshot(ctx context.Context, targetURL string) (string, error)
}

// Server is the main HTTP server for the reporting wizard.
type Server struct {
	config      Config
	store       store.Store
	templates   *template.Template
	discovery   *infra.Discovery
	emailCfg    report.EmailConfig
	rl          *RateLimiter
	router      chi.Router
	staticFS    fs.FS
	snapshotter Snapshotter
	escalator   admin.Escalator
}

// NewServer creates a new Server from the given config, store, and filesystem assets.
func NewServer(cfg Config, s store.Store, templatesFS fs.FS, staticFS fs.FS) (*Server, error) {
	funcMap := template.FuncMap{
		"string": func(v interface{}) string {
			switch val := v.(type) {
			case string:
				return val
			case fmt_Stringer:
				return val.String()
			default:
				return ""
			}
		},
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templatesFS, "*.html", "**/*.html")
	if err != nil {
		return nil, err
	}

	emailCfg := report.EmailConfig{
		XARF: report.XARFConfig{
			ReporterOrg:          "End Network Harassment Inc",
			ReporterOrgDomain:    extractDomain(cfg.BaseURL),
			ReporterContactEmail: cfg.FromEmail,
			ReporterContactName:  cfg.FromName,
		},
		FromAddress:    cfg.FromEmail,
		FromName:       cfg.FromName,
		SendGridAPIKey: cfg.SendGridKey,
	}

	srv := &Server{
		config:    cfg,
		store:     s,
		templates: tmpl,
		discovery: infra.NewDiscovery(),
		emailCfg:  emailCfg,
		rl:        NewRateLimiter(DefaultRateLimiterConfig()),
		staticFS:  staticFS,
	}

	srv.router = srv.routes()
	return srv, nil
}

type fmt_Stringer interface {
	String() string
}

func extractDomain(baseURL string) string {
	s := strings.TrimPrefix(baseURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[:idx]
	}
	return s
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()

	logger := slog.Default()
	r.Use(RequestIDMiddleware)
	r.Use(LoggingMiddleware(logger))
	r.Use(RecoveryMiddleware(logger))
	r.Use(SecurityHeadersMiddleware)
	r.Use(IPRateLimitMiddleware(s.rl, s.rl.config.GeneralRequestsPerMin))
	r.Use(CSRFMiddleware([]byte(s.config.SessionSecret)))
	r.Use(s.SessionMiddleware)

	// Static files.
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(s.staticFS))))

	// Public routes.
	r.Get("/", s.HandleIndex)
	r.Get("/auth/login", s.HandleLogin)
	r.Get("/auth/google", s.HandleGoogleLogin)
	r.Get("/auth/google/callback", s.HandleGoogleCallback)
	r.Get("/auth/github", s.HandleGitHubLogin)
	r.Get("/auth/github/callback", s.HandleGitHubCallback)

	// Authenticated routes.
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth)
		r.Post("/auth/logout", s.HandleLogout)

		// Wizard.
		r.Get("/wizard/step1", s.HandleWizardStep1)
		r.Post("/wizard/step1", s.HandleWizardStep1Submit)
		r.Get("/wizard/step2/{reportID}", s.HandleWizardStep2)
		r.Post("/wizard/step2/{reportID}/cloudflare-ack", s.HandleCloudflareAck)
		r.Get("/wizard/step3/{reportID}", s.HandleWizardStep3)
		r.Post("/wizard/step3/{reportID}", s.HandleWizardStep3Submit)
		r.Get("/wizard/step4/{reportID}", s.HandleWizardStep4)
		r.Post("/wizard/step4/{reportID}/submit", s.HandleWizardStep4Submit)

		// Reports.
		r.Get("/reports", s.HandleReportsList)
		r.Get("/reports/{reportID}", s.HandleReportDetail)
	})

	// Admin routes.
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth)
		r.Use(RequireAdmin)

		ah := admin.NewAdminHandler(s.store, s.discovery, s.emailCfg, s.templates,
			UserFromContext,
			func(ctx context.Context) string { return CSRFTokenFromContext(ctx) },
		)
		if s.escalator != nil {
			ah.SetEscalator(s.escalator)
		}

		r.Get("/admin", ah.HandleDashboard)
		r.Get("/admin/queue", ah.HandleQueue)
		r.Get("/admin/reports/{reportID}", ah.HandleReportView)
		r.Post("/admin/reports/{reportID}/origin-ip", ah.HandleSetOriginIP)
		r.Post("/admin/reports/{reportID}/approve", ah.HandleReportApprove)
		r.Post("/admin/reports/{reportID}/reject", ah.HandleReportReject)
		r.Post("/admin/reports/{reportID}/send-email", ah.HandleSendEmailToUser)
		r.Get("/admin/emails/{emailID}", ah.HandleEmailPreview)
		r.Post("/admin/emails/{emailID}/approve", ah.HandleEmailApprove)
		r.Post("/admin/emails/{emailID}/reject", ah.HandleEmailReject)
		r.Post("/admin/emails/{emailID}/reply-action", ah.HandleReplyAction)
		r.Get("/admin/evidence/{evidenceID}", ah.HandleAdminEvidenceDownload)
		r.Get("/admin/users", ah.HandleListUsers)
		r.Post("/admin/users/{userID}/ban", ah.HandleBanUser)
		r.Post("/admin/users/{userID}/report-abuse", ah.HandleReportAbuse)
	})

	return r
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return s.router
}

// SetSnapshotter configures the URL snapshotter for text-only URL crawling.
func (s *Server) SetSnapshotter(snap Snapshotter) {
	s.snapshotter = snap
}

// SetBoilerplate configures the domain boilerplate database for email composition.
func (s *Server) SetBoilerplate(db *boilerplate.DB) {
	s.emailCfg.Boilerplate = db
}

// SetEscalator configures the escalation engine for admin immediate-escalation actions.
func (s *Server) SetEscalator(e admin.Escalator) {
	s.escalator = e
}

// Stop cleans up server resources.
func (s *Server) Stop() {
	s.rl.Stop()
}

// HandleIndex renders the home page.
func (s *Server) HandleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "index.html", nil)
}

// render executes a template with common data.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["User"] = UserFromContext(r.Context())
	data["CSRFToken"] = CSRFTokenFromContext(r.Context())
	data["RecaptchaSiteKey"] = s.config.RecaptchaSiteKey

	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("ERROR: render template %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
