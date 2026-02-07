package server

import (
	"log"
	"net/http"

	"github.com/endharassment/reporting-wizard/internal/model"
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
	snapshots, _ := s.store.ListURLSnapshotsByReport(r.Context(), reportID)

	type EmailWithReplies struct {
		*model.OutgoingEmail
		Replies []*model.EmailReply
	}
	emailsWithReplies := []EmailWithReplies{}
	for _, email := range emails {
		replies, _ := s.store.ListEmailRepliesByEmail(r.Context(), email.ID)
		emailsWithReplies = append(emailsWithReplies, EmailWithReplies{
			OutgoingEmail: email,
			Replies:       replies,
		})
	}

	s.render(w, r, "detail.html", map[string]interface{}{
		"Report":    rpt,
		"Evidence":  evidence,
		"Emails":    emailsWithReplies,
		"Timeline":  auditLog,
		"Snapshots": snapshots,
	})
}

