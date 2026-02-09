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
	"github.com/endharassment/reporting-wizard/internal/boilerplate"
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
		ListenAddr:         *listenAddr,
		DBPath:             *dbPath,
		SendGridKey:        os.Getenv("WIZARD_SENDGRID_KEY"),
		FromEmail:          envOr("WIZARD_FROM_EMAIL", "reports@endharassment.net"),
		FromName:           envOr("WIZARD_FROM_NAME", "End Network Harassment Inc"),
		BaseURL:            baseURL,
		GoogleClientID:     os.Getenv("WIZARD_GOOGLE_CLIENT_ID"),
		GoogleSecret:       os.Getenv("WIZARD_GOOGLE_SECRET"),
		GitHubClientID:     os.Getenv("WIZARD_GITHUB_CLIENT_ID"),
		GitHubSecret:       os.Getenv("WIZARD_GITHUB_SECRET"),
		RecaptchaSiteKey:   os.Getenv("WIZARD_RECAPTCHA_SITE_KEY"),
		RecaptchaSecretKey: os.Getenv("WIZARD_RECAPTCHA_SECRET_KEY"),
		EscalationDays:     14,
		SessionSecret:      sessionSecret,
		IMAPServer:         os.Getenv("WIZARD_IMAP_SERVER"),
		IMAPUsername:       os.Getenv("WIZARD_IMAP_USERNAME"),
		IMAPPassword:       os.Getenv("WIZARD_IMAP_PASSWORD"),
	}

	srv, err := server.NewServer(cfg, db, tmplFS, stFS)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Set up URL snapshotter. Use tor-fetcher binary if configured,
	// otherwise fall back to plain HTTP.
	if torBin := os.Getenv("WIZARD_TOR_FETCHER_BIN"); torBin != "" {
		torProxy := envOr("WIZARD_TOR_PROXY", "socks5://127.0.0.1:9050")
		srv.SetSnapshotter(snapshot.NewTorBinarySnapshotter(torBin, torProxy))
		log.Printf("URL snapshotter: tor-fetcher (%s via %s)", torBin, torProxy)
	} else {
		srv.SetSnapshotter(snapshot.NewPlainHTTPSnapshotter())
		log.Println("URL snapshotter: plain HTTP (set WIZARD_TOR_FETCHER_BIN to enable Tor)")
	}

	// Initialize domain boilerplate database.
	boilerplateDB := boilerplate.NewDB()
	srv.SetBoilerplate(boilerplateDB)

	// Start escalation engine.
	logger := slog.Default()
	abuseContactLookup := &infra.RDAPAbuseContactLookup{
		RDAP: infra.NewRDAPClient(),
		ASN:  infra.NewASNClient(),
	}
	escalationEngine := escalation.NewEngine(db, abuseContactLookup, cfg.EscalationDays, logger)
	escalationEngine.SetBoilerplate(boilerplateDB)
	srv.SetEscalator(escalationEngine)
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
