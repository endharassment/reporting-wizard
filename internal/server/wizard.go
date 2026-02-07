package server

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/gdrive"
	"github.com/endharassment/reporting-wizard/internal/infra"
	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/endharassment/reporting-wizard/internal/report"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// HandleWizardStep1 renders the URL entry form.
func (s *Server) HandleWizardStep1(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "step1_urls.html", map[string]interface{}{
		"FormValues": map[string]string{},
		"Errors":     map[string]string{},
	})
}

// HandleWizardStep1Submit parses URLs, validates them, and creates a draft report.
func (s *Server) HandleWizardStep1Submit(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	rawURLs := r.FormValue("urls")

	lines := strings.Split(rawURLs, "\n")
	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}

	errors := map[string]string{}
	if len(urls) == 0 {
		errors["URLs"] = "Please enter at least one URL."
	}

	// Validate URLs and check same domain.
	var domain string
	for i, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			errors["URLs"] = fmt.Sprintf("URL #%d is not a valid HTTP(S) URL: %s", i+1, u)
			break
		}
		host := strings.ToLower(parsed.Hostname())
		if domain == "" {
			domain = host
		} else if host != domain {
			errors["URLs"] = fmt.Sprintf("All URLs must be from the same domain. Found %s and %s.", domain, host)
			break
		}
	}

	if len(errors) > 0 {
		s.render(w, r, "step1_urls.html", map[string]interface{}{
			"FormValues": map[string]string{"URLs": rawURLs},
			"Errors":     errors,
		})
		return
	}

	now := time.Now().UTC()
	rpt := &model.Report{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Domain:    domain,
		URLs:      urls,
		Status:    model.StatusDraft,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateReport(r.Context(), rpt); err != nil {
		log.Printf("ERROR: create report: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Best-effort URL text snapshotting. Run asynchronously so the user
	// doesn't have to wait for Tor fetches to complete.
	if s.snapshotter != nil {
		go s.snapshotURLs(rpt.ID, urls)
	}

	http.Redirect(w, r, fmt.Sprintf("/wizard/step2/%s", rpt.ID), http.StatusFound)
}

// HandleWizardStep2 runs infrastructure discovery and renders results.
func (s *Server) HandleWizardStep2(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Check for existing infra results.
	existing, _ := s.store.ListInfraResultsByReport(r.Context(), reportID)
	if len(existing) == 0 {
		// Run discovery.
		results, err := s.discovery.Run(r.Context(), rpt.Domain)
		if err != nil {
			log.Printf("ERROR: infra discovery for %s: %v", rpt.Domain, err)
			s.render(w, r, "step2_infra.html", map[string]interface{}{
				"Report":       rpt,
				"InfraResults": nil,
				"Error":        fmt.Sprintf("Infrastructure discovery failed: %v", err),
			})
			return
		}

		// Store results.
		now := time.Now().UTC()
		for i := range results {
			results[i].ID = uuid.New().String()
			results[i].ReportID = reportID
			results[i].CreatedAt = now
			if err := s.store.CreateInfraResult(r.Context(), &results[i]); err != nil {
				log.Printf("ERROR: store infra result: %v", err)
			}
		}

		// Convert to pointers for template.
		existing = make([]*model.InfraResult, len(results))
		for i := range results {
			existing[i] = &results[i]
		}
	}

	// Check for Cloudflare.
	hasCloudflare := false
	var upstreamASNs []int
	for _, ir := range existing {
		if ir.IsCloudflare {
			hasCloudflare = true
		}
		for _, u := range ir.UpstreamASNs {
			upstreamASNs = append(upstreamASNs, u)
		}
	}

	if hasCloudflare && rpt.CloudflareOriginIP == "" {
		rpt.Status = model.StatusCloudfarePending
		rpt.UpdatedAt = time.Now().UTC()
		_ = s.store.UpdateReport(r.Context(), rpt)

		s.render(w, r, "step2_cloudflare.html", map[string]interface{}{
			"Report":       rpt,
			"InfraResults": existing,
		})
		return
	}

	s.render(w, r, "step2_infra.html", map[string]interface{}{
		"Report":       rpt,
		"InfraResults": existing,
		"UpstreamASNs": dedup(upstreamASNs),
	})
}

// HandleCloudflareAck handles POST /wizard/step2/{reportID}/cloudflare-ack.
func (s *Server) HandleCloudflareAck(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Mark as cloudflare pending and redirect to report detail.
	rpt.Status = model.StatusCloudfarePending
	rpt.UpdatedAt = time.Now().UTC()
	_ = s.store.UpdateReport(r.Context(), rpt)

	http.Redirect(w, r, fmt.Sprintf("/reports/%s", reportID), http.StatusFound)
}

// HandleWizardStep3 renders the evidence form.
func (s *Server) HandleWizardStep3(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	evidence, _ := s.store.ListEvidenceByReport(r.Context(), reportID)

	// Build a string of existing evidence URLs for prepopulation.
	var existingURLs []string
	for _, ev := range evidence {
		if ev.EvidenceURL != "" {
			existingURLs = append(existingURLs, ev.EvidenceURL)
		}
	}

	s.render(w, r, "step3_evidence.html", map[string]interface{}{
		"Report":       rpt,
		"Evidence":     evidence,
		"EvidenceURLs": strings.Join(existingURLs, "\n"),
		"Errors":       map[string]string{},
	})
}

// HandleWizardStep3Submit saves violation type, description, and evidence URLs.
func (s *Server) HandleWizardStep3Submit(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	violationType := r.FormValue("violation_type")
	description := strings.TrimSpace(r.FormValue("description"))
	evidenceURLsRaw := r.FormValue("evidence_urls")

	errors := map[string]string{}
	if violationType == "" {
		errors["ViolationType"] = "Please select a violation type."
	}
	if description == "" {
		errors["Description"] = "Please provide a description."
	}

	// Parse and validate evidence URLs.
	var evidenceURLs []string
	for _, line := range strings.Split(evidenceURLsRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			errors["EvidenceURLs"] = fmt.Sprintf("Invalid URL: %s. Please provide valid HTTP(S) URLs.", line)
			break
		}
		evidenceURLs = append(evidenceURLs, line)
	}

	if len(errors) > 0 {
		evidence, _ := s.store.ListEvidenceByReport(r.Context(), reportID)
		s.render(w, r, "step3_evidence.html", map[string]interface{}{
			"Report":       rpt,
			"Evidence":     evidence,
			"EvidenceURLs": evidenceURLsRaw,
			"Errors":       errors,
		})
		return
	}

	// Store each evidence URL as an evidence record.
	// For Google Drive URLs, attempt metadata verification.
	now := time.Now().UTC()
	for _, u := range evidenceURLs {
		ev := &model.Evidence{
			ID:          uuid.New().String(),
			ReportID:    reportID,
			EvidenceURL: u,
			Description: "User-provided evidence link",
			CreatedAt:   now,
		}

		// If this is a Google Drive URL, try to verify and pull metadata.
		if fileID := gdrive.ExtractFileID(u); fileID != "" {
			ev.DriveFileID = fileID
			ev.Description = "Google Drive evidence link"

			if user.GoogleAccessToken != "" {
				token := &oauth2.Token{
					AccessToken:  user.GoogleAccessToken,
					RefreshToken: user.GoogleRefreshToken,
					Expiry:       user.GoogleTokenExpiry,
				}

				// Refresh token if needed.
				cfg := s.googleOAuthConfig()
				refreshed, err := gdrive.RefreshTokenIfNeeded(r.Context(), cfg, token)
				if err != nil {
					log.Printf("WARN: refresh google token for user %s: %v", user.ID, err)
				} else {
					if refreshed.AccessToken != token.AccessToken {
						user.GoogleAccessToken = refreshed.AccessToken
						user.GoogleTokenExpiry = refreshed.Expiry
						if refreshed.RefreshToken != "" {
							user.GoogleRefreshToken = refreshed.RefreshToken
						}
						_ = s.store.UpdateUser(r.Context(), user)
					}
					token = refreshed

					meta, err := gdrive.GetFileMeta(r.Context(), token, fileID)
					if err != nil {
						log.Printf("WARN: drive metadata for %s: %v", fileID, err)
					} else {
						ev.DriveFileName = meta.Name
						ev.DriveMimeType = meta.MimeType
						ev.DriveSize = meta.Size
						ev.DriveVerified = true
					}
				}
			}
		}

		if err := s.store.CreateEvidence(r.Context(), ev); err != nil {
			log.Printf("ERROR: store evidence URL: %v", err)
		}
	}

	rpt.ViolationType = model.ViolationType(violationType)
	rpt.Description = description
	rpt.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateReport(r.Context(), rpt); err != nil {
		log.Printf("ERROR: update report: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/wizard/step4/%s", reportID), http.StatusFound)
}

// HandleWizardStep4 generates X-ARF preview and renders the review page.
func (s *Server) HandleWizardStep4(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	infraResults, _ := s.store.ListInfraResultsByReport(r.Context(), reportID)
	evidence, _ := s.store.ListEvidenceByReport(r.Context(), reportID)
	snapshots, _ := s.store.ListURLSnapshotsByReport(r.Context(), reportID)

	// Collect unique abuse contacts.
	contactSet := make(map[string]bool)
	for _, ir := range infraResults {
		if ir.AbuseContact != "" {
			contactSet[ir.AbuseContact] = true
		}
	}
	var abuseContacts []string
	for c := range contactSet {
		abuseContacts = append(abuseContacts, c)
	}

	// Generate email preview.
	var emailPreview map[string]string
	if len(infraResults) > 0 {
		outgoing, err := report.ComposeEmail(s.emailCfg, rpt, infraResults, evidence, nil)
		if err == nil {
			emailPreview = map[string]string{
				"Recipient": outgoing.Recipient,
				"Subject":   outgoing.EmailSubject,
				"Body":      outgoing.EmailBody,
			}
		}
	}

	s.render(w, r, "step4_review.html", map[string]interface{}{
		"Report":        rpt,
		"InfraResults":  infraResults,
		"Evidence":      evidence,
		"Snapshots":     snapshots,
		"AbuseContacts": abuseContacts,
		"EmailPreview":  emailPreview,
	})
}

// HandleWizardStep4Submit generates outgoing emails and submits for approval.
func (s *Server) HandleWizardStep4Submit(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	user := UserFromContext(r.Context())

	rpt, err := s.store.GetReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if rpt.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	infraResults, _ := s.store.ListInfraResultsByReport(r.Context(), reportID)
	evidence, _ := s.store.ListEvidenceByReport(r.Context(), reportID)

	// Group infra results by unique abuse contact.
	contactMap := make(map[string][]*model.InfraResult)
	for _, ir := range infraResults {
		if ir.AbuseContact != "" {
			contactMap[ir.AbuseContact] = append(contactMap[ir.AbuseContact], ir)
		}
	}

	// Generate one outgoing email per unique abuse contact.
	for _, results := range contactMap {
		outgoing, err := report.ComposeEmail(s.emailCfg, rpt, results, evidence, nil)
		if err != nil {
			log.Printf("ERROR: compose email: %v", err)
			continue
		}
		if err := s.store.CreateOutgoingEmail(r.Context(), outgoing); err != nil {
			log.Printf("ERROR: create outgoing email: %v", err)
		}
	}

	// If no abuse contacts found, still create a placeholder.
	if len(contactMap) == 0 && len(infraResults) > 0 {
		outgoing, err := report.ComposeEmail(s.emailCfg, rpt, infraResults, evidence, nil)
		if err == nil {
			_ = s.store.CreateOutgoingEmail(r.Context(), outgoing)
		}
	}

	rpt.Status = model.StatusPendingApproval
	rpt.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateReport(r.Context(), rpt); err != nil {
		log.Printf("ERROR: update report status: %v", err)
	}

	http.Redirect(w, r, fmt.Sprintf("/reports/%s", reportID), http.StatusFound)
}

// --- Helpers ---

func dedup(asns []int) []int {
	seen := make(map[int]bool)
	var result []int
	for _, a := range asns {
		if !seen[a] {
			seen[a] = true
			result = append(result, a)
		}
	}
	return result
}

// HasCloudflare checks if any infra results are behind Cloudflare.
func HasCloudflare(results []*model.InfraResult) bool {
	for _, r := range results {
		if infra.IsCloudflare(r.ASN) {
			return true
		}
	}
	return false
}
