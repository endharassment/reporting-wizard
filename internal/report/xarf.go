package report

import (
	"encoding/json"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
)

// XARFReport represents an X-ARF v4 abuse report.
type XARFReport struct {
	Version      string         `json:"Version"`
	ReporterInfo XARFReporter   `json:"ReporterInfo"`
	Report       XARFReportBody `json:"Report"`
	Evidence     []XARFEvidence `json:"Evidence"`
}

// XARFReporter identifies the organization filing the report.
type XARFReporter struct {
	ReporterOrg          string `json:"ReporterOrg"`
	ReporterOrgDomain    string `json:"ReporterOrgDomain"`
	ReporterContactEmail string `json:"ReporterContactEmail"`
	ReporterContactName  string `json:"ReporterContactName"`
}

// XARFReportBody contains the report details.
type XARFReportBody struct {
	ReportClass string   `json:"ReportClass"`
	ReportType  string   `json:"ReportType"`
	Date        string   `json:"Date"`
	SourceIP    string   `json:"SourceIp"`
	SourcePort  int      `json:"SourcePort"`
	Domain      string   `json:"Domain"`
	URLs        []string `json:"URLs"`
	Description string   `json:"Description"`
}

// XARFEvidence represents a piece of evidence in X-ARF format.
type XARFEvidence struct {
	Description string `json:"Description"`
	ContentType string `json:"ContentType,omitempty"`
	SHA256      string `json:"SHA256,omitempty"`
	URL         string `json:"URL,omitempty"`
	Content     string `json:"Content,omitempty"`
}

// XARFConfig holds the reporter identity used in X-ARF reports.
type XARFConfig struct {
	ReporterOrg          string
	ReporterOrgDomain    string
	ReporterContactEmail string
	ReporterContactName  string
}

// maxInlineEvidenceBytes is the maximum size of evidence content to include
// inline (base64-encoded) in the X-ARF JSON. Larger files are referenced
// by hash only.
const maxInlineEvidenceBytes int64 = 1 << 20 // 1 MiB

// violationMapping maps ViolationType to (ReportClass, ReportType).
var violationMapping = map[model.ViolationType][2]string{
	model.ViolationHarassment: {"content", "illegal_content"},
	model.ViolationHateSpeech: {"content", "illegal_content"},
	model.ViolationNCII:       {"content", "illegal_content"},
	model.ViolationDoxxing:    {"content", "illegal_content"},
	model.ViolationCopyvio:    {"copyright", "copyright_infringement"},
}

// GenerateXARF creates an X-ARF v4 JSON report from a model.Report, its
// infrastructure results, and associated evidence.
func GenerateXARF(cfg XARFConfig, report *model.Report, infraResults []*model.InfraResult, evidence []*model.Evidence, evidenceContent map[string]string) ([]byte, error) {
	mapping, ok := violationMapping[report.ViolationType]
	if !ok {
		mapping = [2]string{"content", "illegal_content"}
	}

	sourceIP := ""
	if len(infraResults) > 0 {
		sourceIP = infraResults[0].IP
	}

	xarfEvidence := make([]XARFEvidence, 0, len(evidence))
	for _, e := range evidence {
		xe := XARFEvidence{
			Description: e.Description,
		}
		if e.EvidenceURL != "" {
			xe.URL = e.EvidenceURL
		} else {
			xe.ContentType = e.ContentType
			xe.SHA256 = e.SHA256
			if e.SizeBytes <= maxInlineEvidenceBytes {
				if content, found := evidenceContent[e.ID]; found {
					xe.Content = content
				}
			}
		}
		xarfEvidence = append(xarfEvidence, xe)
	}

	xarf := XARFReport{
		Version: "4",
		ReporterInfo: XARFReporter{
			ReporterOrg:          cfg.ReporterOrg,
			ReporterOrgDomain:    cfg.ReporterOrgDomain,
			ReporterContactEmail: cfg.ReporterContactEmail,
			ReporterContactName:  cfg.ReporterContactName,
		},
		Report: XARFReportBody{
			ReportClass: mapping[0],
			ReportType:  mapping[1],
			Date:        report.CreatedAt.UTC().Format(time.RFC3339),
			SourceIP:    sourceIP,
			SourcePort:  0,
			Domain:      report.Domain,
			URLs:        report.URLs,
			Description: report.Description,
		},
		Evidence: xarfEvidence,
	}

	return json.MarshalIndent(xarf, "", "  ")
}
