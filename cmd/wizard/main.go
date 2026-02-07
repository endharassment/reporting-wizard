package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	wizard "github.com/endharassment/reporting-wizard"
	"github.com/endharassment/reporting-wizard/internal/email"
	"github.com/endharassment/reporting-wizard/internal/escalation"
	"github.com/endharassment/reporting-wizard/internal/infra"
	"github.com/endharassment/reporting-wizard/internal/server"
	"github.com/endharassment/reporting-wizard/internal/snapshot"
	"github.com/endharassment/reporting-wizard/internal/store"
)

func main() {
	listenAddr := flag.String("listen", envOr("WIZARD_LISTEN", ":8080"), "HTTP listen address")
	dbPath := flag.String("db", envOr("WIZARD_DB_PATH", "./wizard.db"), "SQLite database path")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	db, err := store.NewSQLiteStore(ctx, *dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	tmplFS, err := fs.Sub(wizard.TemplatesFS, "templates")
	if err != nil {
		log.Fatalf("Failed to create templates sub-FS: %v", err)
	}
	stFS, err := fs.Sub(wizard.StaticFS, "static")
	if err != nil {
		log.Fatalf("Failed to create static sub-FS: %v", err)
	}

	baseURL := envOr("WIZARD_BASE_URL", "http://localhost:8080")
	sessionSecret := os.Getenv("WIZARD_SESSION_SECRET")
	if sessionSecret == "" || sessionSecret == "change-me-in-production" {
		if strings.HasPrefix(baseURL, "https://") {
			log.Fatal("WIZARD_SESSION_SECRET must be set to a strong random value in production (try: openssl rand -hex 32)")
		}
		// Allow an insecure default for local development only.
		log.Println("WARNING: using insecure default session secret -- set WIZARD_SESSION_SECRET for production")
		sessionSecret = "insecure-dev-only-session-secret-do-not-use"
	}

	cfg := server.Config{
		ListenAddr:     *listenAddr,
		DBPath:         *dbPath,
		SendGridKey:    os.Getenv("WIZARD_SENDGRID_KEY"),
		FromEmail:      envOr("WIZARD_FROM_EMAIL", "reports@endharassment.net"),
		FromName:       envOr("WIZARD_FROM_NAME", "End Network Harassment Inc"),
		BaseURL:        baseURL,
		GoogleClientID: os.Getenv("WIZARD_GOOGLE_CLIENT_ID"),
		GoogleSecret:   os.Getenv("WIZARD_GOOGLE_SECRET"),
		GitHubClientID: os.Getenv("WIZARD_GITHUB_CLIENT_ID"),
		GitHubSecret:   os.Getenv("WIZARD_GITHUB_SECRET"),
		EscalationDays: 14,
		SessionSecret:  sessionSecret,
		IMAPServer:     os.Getenv("WIZARD_IMAP_SERVER"),
		IMAPUsername:   os.Getenv("WIZARD_IMAP_USERNAME"),
		IMAPPassword:   os.Getenv("WIZARD_IMAP_PASSWORD"),
	}

	srv, err := server.NewServer(cfg, db, tmplFS, stFS)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Set up URL snapshotter (plain HTTP; tor-fetcher can be wired in when
	// a local Tor SOCKS proxy is available).
	srv.SetSnapshotter(snapshot.NewPlainHTTPSnapshotter())

	// Start escalation engine.
	logger := slog.Default()
	abuseContactLookup := &infra.RDAPAbuseContactLookup{
		RDAP: infra.NewRDAPClient(),
		ASN:  infra.NewASNClient(),
	}
	escalationEngine := escalation.NewEngine(db, abuseContactLookup, cfg.EscalationDays, logger)
	go func() {
		if err := escalationEngine.Run(ctx); err != nil && err != context.Canceled {
			log.Printf("ERROR: escalation engine: %v", err)
		}
	}()
	log.Println("Escalation engine started")

	// Start email reply fetcher.
	if cfg.IMAPServer != "" {
		imapCfg := email.IMAPConfig{
			Server:   cfg.IMAPServer,
			Username: cfg.IMAPUsername,
			Password: cfg.IMAPPassword,
		}
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					email.FetchAndProcessEmails(imapCfg, db)
				}
			}
		}()
		log.Println("Email reply fetcher started")
	}

	httpSrv := &http.Server{
		Addr:    *listenAddr,
		Handler: srv.Handler(),
	}

	go func() {
		log.Printf("Listening on %s", *listenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
