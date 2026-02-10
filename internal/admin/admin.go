package admin

import (
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/infra"
	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/endharassment/reporting-wizard/internal/report"
	"github.com/endharassment/reporting-wizard/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// UserFunc extracts the authenticated user from a context.
type UserFunc func(ctx context.Context) *model.User

// CSRFFunc extracts the CSRF token from a context.
type CSRFFunc func(ctx context.Context) string

// Escalator triggers immediate escalation for an outgoing email.
type Escalator interface {
	EscalateNow(ctx context.Context, emailID string) (int, error)
}

// AdminHandler holds dependencies for admin route handlers.
type AdminHandler struct {
	store     store.Store
	discovery *infra.Discovery
	emailCfg  report.EmailConfig
	templates *template.Template
	getUser   UserFunc
	getCSRF   CSRFFunc
	escalator Escalator
	baseURL   string
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(s store.Store, d *infra.Discovery, emailCfg report.EmailConfig, tmpl *template.Template, getUser UserFunc, getCSRF CSRFFunc, baseURL string) *AdminHandler {
	return &AdminHandler{
		store:     s,
		discovery: d,
		emailCfg:  emailCfg,
		templates: tmpl,
		getUser:   getUser,
		getCSRF:   getCSRF,
		baseURL:   baseURL,
	}
}

// SetEscalator configures the escalation engine for immediate escalation actions.
func (h *AdminHandler) SetEscalator(e Escalator) {
	h.escalator = e
}

// DashboardCounts holds the counts shown on the admin dashboard.
type DashboardCounts struct {
	PendingApproval   int
	Sent              int
	Escalating        int
	CloudflarePending int
}

// HandleDashboard renders the admin dashboard.
func (h *AdminHandler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	pending, _ := h.store.ListEmailsByStatus(r.Context(), model.EmailPendingApproval)
	sent, _ := h.store.ListEmailsByStatus(r.Context(), model.EmailSent)
	escalating, _ := h.store.ListReportsByStatus(r.Context(), model.StatusEscalating)
	cfPending, _ := h.store.ListReportsByStatus(r.Context(), model.StatusCloudfarePending)

	counts := DashboardCounts{
		PendingApproval:   len(pending),
		Sent:              len(sent),
		Escalating:        len(escalating),
		CloudflarePending: len(cfPending),
	}

	h.render(w, r, "dashboard.html", map[string]interface{}{
		"Counts": counts,
	})
}

// HandleQueue renders the email approval queue.
func (h *AdminHandler) HandleQueue(w http.ResponseWriter, r *http.Request) {
	pending, err := h.store.ListEmailsByStatus(r.Context(), model.EmailPendingApproval)
	if err != nil {
		log.Printf("ERROR: list pending emails: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.render(w, r, "queue.html", map[string]interface{}{
		"PendingEmails": pending,
	})
}

// HandleReportView renders the admin report detail page.
func (h *AdminHandler) HandleReportView(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")

	rpt, err := h.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	evidence, _ := h.store.ListEvidenceByReport(r.Context(), reportID)
	emails, _ := h.store.ListEmailsByReport(r.Context(), reportID)
	repliesByEmail, _ := h.store.ListAllRepliesByReport(r.Context(), reportID)
	auditLog, _ := h.store.ListAuditLogByTarget(r.Context(), reportID)

	h.render(w, r, "report.html", map[string]interface{}{
		"Report":         rpt,
		"Evidence":       evidence,
		"Emails":         emails,
		"RepliesByEmail": repliesByEmail,
		"AuditLog":       auditLog,
	})
}

// HandleEmailPreview shows email details for review.
func (h *AdminHandler) HandleEmailPreview(w http.ResponseWriter, r *http.Request) {
	emailID := chi.URLParam(r, "emailID")

	email, err := h.store.GetOutgoingEmail(r.Context(), emailID)
	if err != nil {
		http.Error(w, "Email not found", http.StatusNotFound)
		return
	}

	rpt, _ := h.store.GetReport(r.Context(), email.ReportID)

	h.render(w, r, "queue.html", map[string]interface{}{
		"Email":  email,
		"Report": rpt,
	})
}

// HandleEmailApprove approves an email and triggers sending.
func (h *AdminHandler) HandleEmailApprove(w http.ResponseWriter, r *http.Request) {
	emailID := chi.URLParam(r, "emailID")
	user := h.getUser(r.Context())

	email, err := h.store.GetOutgoingEmail(r.Context(), emailID)
	if err != nil {
		http.Error(w, "Email not found", http.StatusNotFound)
		return
	}

	now := time.Now().UTC()
	email.Status = model.EmailApproved
	email.ApprovedBy = user.ID
	email.ApprovedAt = &now

	if err := h.store.UpdateOutgoingEmail(r.Context(), email); err != nil {
		log.Printf("ERROR: approve email: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Attempt to send via SendGrid.
	if h.emailCfg.SendGridAPIKey != "" {
		sender := &report.RealSendGridSender{APIKey: h.emailCfg.SendGridAPIKey}
		result, err := report.SendEmail(sender, h.emailCfg, email)
		if err != nil {
			log.Printf("ERROR: send email %s: %v", emailID, err)
		} else {
			sentAt := time.Now().UTC()
			email.Status = model.EmailSent
			email.SentAt = &sentAt
			email.SendGridID = result.MessageID

			// Set escalation timer.
			escalateAt := sentAt.Add(14 * 24 * time.Hour) // default 14 days
			email.EscalateAfter = &escalateAt

			_ = h.store.UpdateOutgoingEmail(r.Context(), email)
		}
	} else {
		log.Printf("INFO: SendGrid not configured; email %s approved but not sent", emailID)
	}

	// Create audit log entry.
	h.createAuditEntry(r, user.ID, "email_approved", emailID, fmt.Sprintf("Email to %s approved", email.Recipient))

	// For htmx requests, return a replacement row.
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<tr id="email-%s"><td colspan="5">Approved</td></tr>`, emailID)
		return
	}

	http.Redirect(w, r, "/admin/queue", http.StatusFound)
}

// HandleEmailReject rejects an email.
func (h *AdminHandler) HandleEmailReject(w http.ResponseWriter, r *http.Request) {
	emailID := chi.URLParam(r, "emailID")
	user := h.getUser(r.Context())

	email, err := h.store.GetOutgoingEmail(r.Context(), emailID)
	if err != nil {
		http.Error(w, "Email not found", http.StatusNotFound)
		return
	}

	notes := r.FormValue("notes")
	email.Status = model.EmailRejected
	email.ResponseNotes = notes

	if err := h.store.UpdateOutgoingEmail(r.Context(), email); err != nil {
		log.Printf("ERROR: reject email: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.createAuditEntry(r, user.ID, "email_rejected", emailID, fmt.Sprintf("Email to %s rejected: %s", email.Recipient, notes))

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<tr id="email-%s"><td colspan="5">Rejected</td></tr>`, emailID)
		return
	}

	http.Redirect(w, r, "/admin/queue", http.StatusFound)
}

// HandleReportApprove approves all pending emails for a report.
func (h *AdminHandler) HandleReportApprove(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := h.getUser(r.Context())

	emails, _ := h.store.ListEmailsByReport(r.Context(), reportID)
	for _, email := range emails {
		if email.Status != model.EmailPendingApproval {
			continue
		}
		now := time.Now().UTC()
		email.Status = model.EmailApproved
		email.ApprovedBy = user.ID
		email.ApprovedAt = &now
		_ = h.store.UpdateOutgoingEmail(r.Context(), email)

		if h.emailCfg.SendGridAPIKey != "" {
			sender := &report.RealSendGridSender{APIKey: h.emailCfg.SendGridAPIKey}
			result, err := report.SendEmail(sender, h.emailCfg, email)
			if err != nil {
				log.Printf("ERROR: send email %s: %v", email.ID, err)
			} else {
				sentAt := time.Now().UTC()
				email.Status = model.EmailSent
				email.SentAt = &sentAt
				email.SendGridID = result.MessageID
				escalateAt := sentAt.Add(14 * 24 * time.Hour)
				email.EscalateAfter = &escalateAt
				_ = h.store.UpdateOutgoingEmail(r.Context(), email)
			}
		}
	}

	rpt, _ := h.store.GetReport(r.Context(), reportID)
	if rpt != nil {
		rpt.Status = model.StatusSent
		rpt.UpdatedAt = time.Now().UTC()
		_ = h.store.UpdateReport(r.Context(), rpt)
	}

	h.createAuditEntry(r, user.ID, "report_approved", reportID, "All emails approved and queued for sending")

	http.Redirect(w, r, fmt.Sprintf("/admin/reports/%s", reportID), http.StatusFound)
}

// HandleReportReject rejects all pending emails for a report.
func (h *AdminHandler) HandleReportReject(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := h.getUser(r.Context())
	notes := r.FormValue("notes")

	emails, _ := h.store.ListEmailsByReport(r.Context(), reportID)
	for _, email := range emails {
		if email.Status != model.EmailPendingApproval {
			continue
		}
		email.Status = model.EmailRejected
		email.ResponseNotes = notes
		_ = h.store.UpdateOutgoingEmail(r.Context(), email)
	}

	h.createAuditEntry(r, user.ID, "report_rejected", reportID, fmt.Sprintf("Report rejected: %s", notes))

	http.Redirect(w, r, fmt.Sprintf("/admin/reports/%s", reportID), http.StatusFound)
}

// HandleSetOriginIP handles setting a Cloudflare origin IP for a report.
func (h *AdminHandler) HandleSetOriginIP(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := h.getUser(r.Context())
	originIP := r.FormValue("origin_ip")

	// Validate IP.
	if net.ParseIP(originIP) == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	rpt, err := h.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	rpt.CloudflareOriginIP = originIP
	rpt.UpdatedAt = time.Now().UTC()
	if err := h.store.UpdateReport(r.Context(), rpt); err != nil {
		log.Printf("ERROR: update report origin IP: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Delete old infra results and re-run discovery with the origin IP.
	if err := h.store.DeleteInfraResultsByReport(r.Context(), reportID); err != nil {
		log.Printf("ERROR: delete old infra results: %v", err)
	}

	// Run discovery using the origin IP directly.
	disc, err := h.discovery.Run(r.Context(), rpt.Domain)
	if err != nil {
		log.Printf("WARN: re-discovery for %s failed: %v", rpt.Domain, err)
	}

	if disc != nil {
		now := time.Now().UTC()
		for i := range disc.InfraResults {
			disc.InfraResults[i].ID = uuid.New().String()
			disc.InfraResults[i].ReportID = reportID
			disc.InfraResults[i].CreatedAt = now
			if err := h.store.CreateInfraResult(r.Context(), &disc.InfraResults[i]); err != nil {
				log.Printf("ERROR: store infra result: %v", err)
			}
		}

		// Cache the full upstream graph for escalation.
		for asn, upstreams := range disc.UpstreamGraph {
			if err := h.store.UpsertUpstreamCache(r.Context(), asn, upstreams); err != nil {
				log.Printf("ERROR: cache upstream for AS%d: %v", asn, err)
			}
		}
	}

	// Update report status from cloudflare_pending to draft so the user
	// can continue through the wizard.
	rpt.Status = model.StatusDraft
	rpt.UpdatedAt = time.Now().UTC()
	_ = h.store.UpdateReport(r.Context(), rpt)

	h.createAuditEntry(r, user.ID, "origin_ip_set", reportID, fmt.Sprintf("Origin IP set to %s", originIP))

	http.Redirect(w, r, fmt.Sprintf("/admin/reports/%s", reportID), http.StatusFound)
}

// HandleAdminEvidenceDownload serves evidence files for admin review.
func (h *AdminHandler) HandleAdminEvidenceDownload(w http.ResponseWriter, r *http.Request) {
	evidenceID := chi.URLParam(r, "evidenceID")

	ev, err := h.store.GetEvidence(r.Context(), evidenceID)
	if err != nil {
		http.Error(w, "Evidence not found", http.StatusNotFound)
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
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(ev.Filename)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, ev.Filename, ev.CreatedAt, f)
}

// HandleListUsers renders the user management page.
func (h *AdminHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		log.Printf("ERROR: list users: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "users.html", map[string]interface{}{
		"Users": users,
	})
}

// HandleBanUser bans a user.
func (h *AdminHandler) HandleBanUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	adminUser := h.getUser(r.Context())

	if err := h.store.BanUser(r.Context(), userID); err != nil {
		log.Printf("ERROR: ban user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.createAuditEntry(r, adminUser.ID, "user_banned", userID, fmt.Sprintf("User %s banned", userID))

	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

// HandleReportAbuse reports a user to their identity provider.
func (h *AdminHandler) HandleReportAbuse(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	adminUser := h.getUser(r.Context())

	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		log.Printf("ERROR: get user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	provider := "unknown"
	reportURL := ""
	if user.GoogleRefreshToken != "" {
		provider = "Google"
		reportURL = "https://support.google.com/mail/answer/8253"
	} else if strings.Contains(user.Email, "@") {
		// Basic check if email contains '@', could be GitHub or other
		provider = "the user's email provider"
		reportURL = "about:blank" // Placeholder
	}

	h.createAuditEntry(r, adminUser.ID, "user_abuse_report_generated", userID, fmt.Sprintf("Generated abuse report for user %s to %s", user.ID, provider))

	h.render(w, r, "report_abuse.html", map[string]interface{}{
		"ReportedUser": user,
		"Provider":     provider,
		"ReportURL":    reportURL,
	})
}

// HandleSendEmailToUser sends a custom email to the user who filed the report.
func (h *AdminHandler) HandleSendEmailToUser(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	adminUser := h.getUser(r.Context())
	subject := r.FormValue("subject")
	message := r.FormValue("message")

	rpt, err := h.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	user, err := h.store.GetUser(r.Context(), rpt.UserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := report.SendEmailToUser(h.emailCfg, user.Email, subject, message); err != nil {
		log.Printf("ERROR: send email to user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	details := fmt.Sprintf("Sent email to user %s with subject: %s", user.Email, subject)
	h.createAuditEntry(r, adminUser.ID, "sent_user_email", reportID, details)

	http.Redirect(w, r, fmt.Sprintf("/admin/reports/%s", reportID), http.StatusFound)
}

// HandleReplyAction processes admin actions on email replies.
// Supported actions: resolve, escalate_now, ignore_autoreply.
func (h *AdminHandler) HandleReplyAction(w http.ResponseWriter, r *http.Request) {
	emailID := chi.URLParam(r, "emailID")
	user := h.getUser(r.Context())
	action := r.FormValue("action")
	notes := r.FormValue("notes")

	email, err := h.store.GetOutgoingEmail(r.Context(), emailID)
	if err != nil {
		http.Error(w, "Email not found", http.StatusNotFound)
		return
	}

	switch action {
	case "resolve":
		resolveNotes := "resolved"
		if notes != "" {
			resolveNotes = "resolved: " + notes
		}
		email.ResponseNotes = resolveNotes
		if err := h.store.UpdateOutgoingEmail(r.Context(), email); err != nil {
			log.Printf("ERROR: resolve email: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Update report status to resolved.
		rpt, err := h.store.GetReport(r.Context(), email.ReportID)
		if err == nil {
			rpt.Status = model.StatusResolved
			rpt.UpdatedAt = time.Now().UTC()
			_ = h.store.UpdateReport(r.Context(), rpt)
		}

		// Cancel pending escalation emails for this report.
		reportEmails, _ := h.store.ListEmailsByReport(r.Context(), email.ReportID)
		for _, re := range reportEmails {
			if re.Status == model.EmailPendingApproval && re.EmailType == model.EmailTypeEscalation {
				re.Status = model.EmailRejected
				re.ResponseNotes = "cancelled: report resolved"
				_ = h.store.UpdateOutgoingEmail(r.Context(), re)
			}
		}

		h.createAuditEntry(r, user.ID, "reply_resolved", emailID,
			fmt.Sprintf("Marked email to %s as resolved: %s", email.Recipient, notes))

	case "escalate_now":
		if h.escalator == nil {
			http.Error(w, "Escalation engine not configured", http.StatusInternalServerError)
			return
		}

		created, err := h.escalator.EscalateNow(r.Context(), emailID)
		if err != nil {
			log.Printf("ERROR: escalate now: %v", err)
			http.Error(w, "Escalation failed", http.StatusInternalServerError)
			return
		}

		h.createAuditEntry(r, user.ID, "reply_escalate_now", emailID,
			fmt.Sprintf("Immediate escalation triggered for email to %s, %d escalation emails created", email.Recipient, created))

	case "ignore_autoreply":
		email.ResponseNotes = ""
		if err := h.store.UpdateOutgoingEmail(r.Context(), email); err != nil {
			log.Printf("ERROR: clear response notes: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		h.createAuditEntry(r, user.ID, "reply_ignore_autoreply", emailID,
			fmt.Sprintf("Auto-reply ignored for email to %s, escalation timer resumed", email.Recipient))

	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/reports/%s", email.ReportID), http.StatusFound)
}

// --- Invites ---

// HandleListInvites renders the invite management page.
func (h *AdminHandler) HandleListInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := h.store.ListInvites(r.Context())
	if err != nil {
		log.Printf("ERROR: list invites: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	users, _ := h.store.ListUsers(r.Context())
	userNames := make(map[string]string)
	for _, u := range users {
		userNames[u.ID] = u.Name
	}

	h.render(w, r, "invites.html", map[string]interface{}{
		"Invites":   invites,
		"UserNames": userNames,
		"BaseURL":   h.baseURL,
	})
}

// HandleCreateInvite creates a new invite code.
func (h *AdminHandler) HandleCreateInvite(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r.Context())

	email := strings.TrimSpace(r.FormValue("email"))
	maxUses := 1
	if v := r.FormValue("max_uses"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxUses = n
		}
	}

	var expiresAt time.Time
	if v := r.FormValue("expires_at"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			expiresAt = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second).UTC()
		}
	}

	invite := &model.Invite{
		ID:        uuid.New().String(),
		Code:      generateInviteCode(),
		Email:     email,
		CreatedBy: user.ID,
		MaxUses:   maxUses,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
	}

	if err := h.store.CreateInvite(r.Context(), invite); err != nil {
		log.Printf("ERROR: create invite: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.createAuditEntry(r, user.ID, "invite_created", invite.ID,
		fmt.Sprintf("Invite code %s created (email=%s, max_uses=%d)", invite.Code, email, maxUses))

	http.Redirect(w, r, "/admin/invites", http.StatusFound)
}

// HandleRevokeInvite revokes an existing invite.
func (h *AdminHandler) HandleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	inviteID := chi.URLParam(r, "inviteID")
	user := h.getUser(r.Context())

	if err := h.store.RevokeInvite(r.Context(), inviteID); err != nil {
		log.Printf("ERROR: revoke invite: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.createAuditEntry(r, user.ID, "invite_revoked", inviteID, "Invite revoked")

	http.Redirect(w, r, "/admin/invites", http.StatusFound)
}

func generateInviteCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// --- Helpers ---

func (h *AdminHandler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["User"] = h.getUser(r.Context())
	data["CSRFToken"] = h.getCSRF(r.Context())

	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("ERROR: render template %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AdminHandler) createAuditEntry(r *http.Request, userID, action, targetID, details string) {
	entry := &model.AuditLogEntry{
		ID:        uuid.New().String(),
		UserID:    userID,
		Action:    action,
		TargetID:  targetID,
		Details:   details,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.store.CreateAuditLogEntry(r.Context(), entry); err != nil {
		log.Printf("ERROR: create audit log: %v", err)
	}
}
