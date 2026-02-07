package report

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// EmailConfig holds settings for composing and sending emails.
type EmailConfig struct {
	XARF        XARFConfig
	FromAddress string
	FromName    string
	// SandboxMode when true prevents actual email delivery via SendGrid.
	SandboxMode bool
	// SendGridAPIKey is the API key for SendGrid.
	SendGridAPIKey string
}

// ComposeEmail builds a model.OutgoingEmail from a report, its infrastructure
// results, and evidence. It generates both a human-readable body and an X-ARF
// JSON attachment.
func ComposeEmail(cfg EmailConfig, report *model.Report, infraResults []*model.InfraResult, evidence []*model.Evidence, evidenceContent map[string]string) (*model.OutgoingEmail, error) {
	xarfJSON, err := GenerateXARF(cfg.XARF, report, infraResults, evidence, evidenceContent)
	if err != nil {
		return nil, fmt.Errorf("generating X-ARF: %w", err)
	}

	// Pick the first abuse contact; caller should create one email per target.
	recipient := ""
	recipientOrg := ""
	targetASN := 0
	if len(infraResults) > 0 {
		recipient = infraResults[0].AbuseContact
		recipientOrg = infraResults[0].ASNName
		targetASN = infraResults[0].ASN
	}

	subject := fmt.Sprintf("Abuse Report: %s violation on %s", violationLabel(report.ViolationType), report.Domain)

	body := composeBody(cfg, report, infraResults, evidence)

	return &model.OutgoingEmail{
		ReportID:     report.ID,
		Recipient:    recipient,
		RecipientOrg: recipientOrg,
		TargetASN:    targetASN,
		EmailType:    model.EmailTypeInitialReport,
		XARFJson:     string(xarfJSON),
		EmailSubject: subject,
		EmailBody:    body,
		Status:       model.EmailPendingApproval,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

func composeBody(cfg EmailConfig, report *model.Report, infraResults []*model.InfraResult, evidence []*model.Evidence) string {
	var b strings.Builder

	b.WriteString("Dear Abuse Team,\n\n")
	b.WriteString(fmt.Sprintf("We are writing on behalf of an affected individual to report a %s violation hosted on the domain %s, and to request that you take action under your acceptable use policy.\n\n", violationLabel(report.ViolationType), report.Domain))

	// Add context-specific disclaimers.
	switch report.ViolationType {
	case model.ViolationNCII:
		b.WriteString("This report is filed on behalf of the person depicted in the non-consensual intimate imagery, or their authorized representative.\n\n")
	case model.ViolationCopyvio:
		b.WriteString("NOTE: This is a Terms of Service abuse report, not a DMCA takedown notice. We are requesting that you review this content under your acceptable use policy.\n\n")
	}

	b.WriteString("Reported URLs:\n")
	for _, u := range report.URLs {
		b.WriteString(fmt.Sprintf("  - %s\n", u))
	}
	b.WriteString("\n")

	b.WriteString("Description:\n")
	b.WriteString(report.Description)
	b.WriteString("\n\n")

	if len(infraResults) > 0 {
		b.WriteString("Infrastructure Details:\n")
		for _, ir := range infraResults {
			b.WriteString(fmt.Sprintf("  - IP: %s (AS%d %s, %s)\n", ir.IP, ir.ASN, ir.ASNName, ir.Country))
		}
		b.WriteString("\n")
	}

	if len(evidence) > 0 {
		b.WriteString("Evidence:\n")
		for _, e := range evidence {
			if e.EvidenceURL != "" {
				b.WriteString(fmt.Sprintf("  - %s\n", e.EvidenceURL))
			} else {
				b.WriteString(fmt.Sprintf("  - %s (%s, SHA-256: %s)\n", e.Filename, e.ContentType, e.SHA256))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("A machine-readable X-ARF v4 report is attached to this email as a JSON file.\n\n")
	b.WriteString("We request that you investigate this matter and take appropriate action in accordance with your acceptable use policy.\n\n")
	b.WriteString("Regards,\n")
	b.WriteString(fmt.Sprintf("%s\n", cfg.XARF.ReporterOrg))
	b.WriteString(fmt.Sprintf("%s <%s>\n", cfg.XARF.ReporterContactName, cfg.XARF.ReporterContactEmail))

	return b.String()
}

func violationLabel(vt model.ViolationType) string {
	switch vt {
	case model.ViolationHarassment:
		return "harassment"
	case model.ViolationHateSpeech:
		return "hate speech"
	case model.ViolationNCII:
		return "non-consensual intimate imagery (NCII)"
	case model.ViolationDoxxing:
		return "doxxing"
	case model.ViolationCopyvio:
		return "copyright infringement"
	default:
		return string(vt)
	}
}

// SendGridSender is the interface for sending emails via SendGrid.
// This abstraction allows for easy mocking in tests.
type SendGridSender interface {
	Send(email *mail.SGMailV3) (*SendResult, error)
}

// SendResult contains the result of sending an email.
type SendResult struct {
	StatusCode int
	MessageID  string
}

// RealSendGridSender sends emails via the SendGrid API.
type RealSendGridSender struct {
	APIKey string
}

// Send dispatches an email through the SendGrid API.
func (s *RealSendGridSender) Send(email *mail.SGMailV3) (*SendResult, error) {
	client := sendgrid.NewSendClient(s.APIKey)
	resp, err := client.Send(email)
	if err != nil {
		return nil, fmt.Errorf("sendgrid send: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("sendgrid returned status %d: %s", resp.StatusCode, resp.Body)
	}
	messageID := ""
	if ids, ok := resp.Headers["X-Message-Id"]; ok && len(ids) > 0 {
		messageID = ids[0]
	}
	return &SendResult{
		StatusCode: resp.StatusCode,
		MessageID:  messageID,
	}, nil
}

// SendEmail sends an OutgoingEmail via the provided SendGridSender.
// When sandboxMode is true, the SendGrid sandbox mail setting is enabled,
// which validates the request without delivering the message.
func SendEmail(sender SendGridSender, cfg EmailConfig, outgoing *model.OutgoingEmail) (*SendResult, error) {
	from := mail.NewEmail(cfg.FromName, cfg.FromAddress)
	to := mail.NewEmail(outgoing.RecipientOrg, outgoing.Recipient)

	message := mail.NewSingleEmail(from, outgoing.EmailSubject, to, outgoing.EmailBody, "")

	// Attach X-ARF JSON report.
	attachment := mail.NewAttachment()
	attachment.SetContent(base64.StdEncoding.EncodeToString([]byte(outgoing.XARFJson)))
	attachment.SetType("application/json")
	attachment.SetFilename("xarf-report.json")
	attachment.SetDisposition("attachment")
	message.AddAttachment(attachment)

	if cfg.SandboxMode {
		settings := mail.NewMailSettings()
		settings.SetSandboxMode(mail.NewSetting(true))
		message.SetMailSettings(settings)
	}

	return sender.Send(message)
}
