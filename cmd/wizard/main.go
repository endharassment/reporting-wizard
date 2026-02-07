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
	"syscall"
	"time"

	wizard "github.com/endharassment/reporting-wizard"
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

	cfg := server.Config{
		ListenAddr:     *listenAddr,
		DBPath:         *dbPath,
		SendGridKey:    os.Getenv("WIZARD_SENDGRID_KEY"),
		FromEmail:      envOr("WIZARD_FROM_EMAIL", "reports@endharassment.net"),
		FromName:       envOr("WIZARD_FROM_NAME", "End Harassment"),
		BaseURL:        envOr("WIZARD_BASE_URL", "http://localhost:8080"),
		GoogleClientID: os.Getenv("WIZARD_GOOGLE_CLIENT_ID"),
		GoogleSecret:   os.Getenv("WIZARD_GOOGLE_SECRET"),
		GitHubClientID: os.Getenv("WIZARD_GITHUB_CLIENT_ID"),
		GitHubSecret:   os.Getenv("WIZARD_GITHUB_SECRET"),
		EscalationDays: 14,
		SessionSecret:  envOr("WIZARD_SESSION_SECRET", "change-me-in-production"),
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
