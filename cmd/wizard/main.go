package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	wizard "github.com/endharassment/reporting-wizard"
	"github.com/endharassment/reporting-wizard/internal/server"
	"github.com/endharassment/reporting-wizard/internal/store"
)

func main() {
	listenAddr := flag.String("listen", envOr("WIZARD_LISTEN", ":8080"), "HTTP listen address")
	dbPath := flag.String("db", envOr("WIZARD_DB_PATH", "./wizard.db"), "SQLite database path")
	evidenceDir := flag.String("evidence-dir", envOr("WIZARD_EVIDENCE_DIR", "./evidence"), "Evidence storage directory")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	db, err := store.NewSQLiteStore(ctx, *dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Ensure evidence directory exists.
	if err := os.MkdirAll(*evidenceDir, 0o750); err != nil {
		log.Fatalf("Failed to create evidence directory: %v", err)
	}

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
		EvidenceDir:    *evidenceDir,
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

	log.Println("Escalation engine started (placeholder)")

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
