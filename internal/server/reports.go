package server

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
)

// HandleReportsList renders the current user's reports.
func (s *Server) HandleReportsList(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())

	reports, err := s.store.ListReportsByUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("ERROR: list reports: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	s.render(w, r, "list.html", map[string]interface{}{
		"Reports": reports,
	})
}

// HandleReportDetail renders a single report with all its associated data.
func (s *Server) HandleReportDetail(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID && !user.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	evidence, _ := s.store.ListEvidenceByReport(r.Context(), reportID)
	emails, _ := s.store.ListEmailsByReport(r.Context(), reportID)
	auditLog, _ := s.store.ListAuditLogByTarget(r.Context(), reportID)

	s.render(w, r, "detail.html", map[string]interface{}{
		"Report":   rpt,
		"Evidence": evidence,
		"Emails":   emails,
		"Timeline": auditLog,
	})
}

// HandleEvidenceDownload serves an evidence file. Only the report owner or an
// admin may download it.
func (s *Server) HandleEvidenceDownload(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	evidenceID := chi.URLParam(r, "evidenceID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID && !user.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	ev, err := s.store.GetEvidence(r.Context(), evidenceID)
	if err != nil {
		http.Error(w, "Evidence not found", http.StatusNotFound)
		return
	}
	if ev.ReportID != reportID {
		http.Error(w, "Evidence not found", http.StatusNotFound)
		return
	}

	// Ensure the storage path is within the evidence directory.
	absPath, err := filepath.Abs(ev.StoragePath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	absEvidenceDir, err := filepath.Abs(s.config.EvidenceDir)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !filepath.HasPrefix(absPath, absEvidenceDir) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	f, err := os.Open(ev.StoragePath)
	if err != nil {
		log.Printf("ERROR: open evidence file: %v", err)
		http.Error(w, "Evidence file not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", ev.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+ev.Filename+"\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, ev.Filename, ev.CreatedAt, f)
}
