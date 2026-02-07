package infra

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/ammario/ipisp/v2"
	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/openrdap/rdap"
)

// --- Mock DNS Resolver ---

type mockDNSResolver struct {
	ip4s map[string][]net.IP
	ip6s map[string][]net.IP
	errs map[string]error
}

func (m *mockDNSResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	if e, ok := m.errs[host]; ok {
		return nil, e
	}
	switch network {
	case "ip4":
		return m.ip4s[host], nil
	case "ip6":
		return m.ip6s[host], nil
	}
	return nil, nil
}

// --- Mock ASN Client ---

type mockASNClient struct {
	results map[string]*ipisp.Response
	errs    map[string]error
}

func (m *mockASNClient) LookupIP(_ context.Context, ip net.IP) (*ipisp.Response, error) {
	key := ip.String()
	if e, ok := m.errs[key]; ok {
		return nil, e
	}
	if r, ok := m.results[key]; ok {
		return r, nil
	}
	return &ipisp.Response{}, nil
}

// --- Mock RDAP Client ---

type mockRDAPClient struct {
	results map[string]*rdap.IPNetwork
	errs    map[string]error
}

func (m *mockRDAPClient) LookupIP(_ context.Context, ip string) (*rdap.IPNetwork, error) {
	if e, ok := m.errs[ip]; ok {
		return nil, e
	}
	if r, ok := m.results[ip]; ok {
		return r, nil
	}
	return &rdap.IPNetwork{}, nil
}

// --- Mock BGP Client ---

type mockBGPClient struct {
	results map[int][]int
	errs    map[int]error
}

func (m *mockBGPClient) LookupUpstreams(_ context.Context, asn int) ([]int, error) {
	if e, ok := m.errs[asn]; ok {
		return nil, e
	}
	return m.results[asn], nil
}

// --- DNS Tests ---

func TestLookupDomain(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		ip4s      map[string][]net.IP
		ip6s      map[string][]net.IP
		errs      map[string]error
		wantCount int
		wantErr   bool
	}{
		{
			name:   "A records only",
			domain: "example.com",
			ip4s: map[string][]net.IP{
				"example.com": {net.ParseIP("93.184.216.34")},
			},
			ip6s:      map[string][]net.IP{},
			wantCount: 1,
		},
		{
			name:   "A and AAAA records",
			domain: "dual.example.com",
			ip4s: map[string][]net.IP{
				"dual.example.com": {net.ParseIP("1.2.3.4")},
			},
			ip6s: map[string][]net.IP{
				"dual.example.com": {net.ParseIP("2001:db8::1")},
			},
			wantCount: 2,
		},
		{
			name:   "multiple A records",
			domain: "multi.example.com",
			ip4s: map[string][]net.IP{
				"multi.example.com": {
					net.ParseIP("1.1.1.1"),
					net.ParseIP("1.0.0.1"),
				},
			},
			ip6s:      map[string][]net.IP{},
			wantCount: 2,
		},
		{
			name:   "no records found",
			domain: "nonexistent.example.com",
			ip4s:   map[string][]net.IP{},
			ip6s:   map[string][]net.IP{},
			errs: map[string]error{
				"nonexistent.example.com": &net.DNSError{
					Err:        "no such host",
					Name:       "nonexistent.example.com",
					IsNotFound: true,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &mockDNSResolver{
				ip4s: tt.ip4s,
				ip6s: tt.ip6s,
				errs: tt.errs,
			}
			results, err := LookupDomain(context.Background(), resolver, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LookupDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(results) != tt.wantCount {
				t.Errorf("LookupDomain() got %d results, want %d", len(results), tt.wantCount)
			}
		})
	}
}

// --- ASN Tests ---

func TestLookupASN(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("93.184.216.0/24")
	tests := []struct {
		name    string
		ip      string
		resp    *ipisp.Response
		wantASN int
		wantErr bool
	}{
		{
			name: "valid lookup",
			ip:   "93.184.216.34",
			resp: &ipisp.Response{
				ASN:     15133,
				ISPName: "Edgecast Inc.",
				Range:   prefix,
				Country: "US",
			},
			wantASN: 15133,
		},
		{
			name:    "invalid IP",
			ip:      "not-an-ip",
			wantErr: true,
		},
		{
			name: "Cloudflare ASN",
			ip:   "104.16.0.1",
			resp: &ipisp.Response{
				ASN:     13335,
				ISPName: "Cloudflare, Inc.",
				Range:   prefix,
				Country: "US",
			},
			wantASN: 13335,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockASNClient{
				results: map[string]*ipisp.Response{},
			}
			if tt.resp != nil {
				client.results[tt.ip] = tt.resp
			}

			info, err := LookupASN(context.Background(), client, tt.ip)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LookupASN() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && info.ASN != tt.wantASN {
				t.Errorf("LookupASN() ASN = %d, want %d", info.ASN, tt.wantASN)
			}
		})
	}
}

// --- Cloudflare Tests ---

func TestIsCloudflare(t *testing.T) {
	tests := []struct {
		name string
		asn  int
		want bool
	}{
		{"Cloudflare ASN", 13335, true},
		{"non-Cloudflare ASN", 15169, false},
		{"zero ASN", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCloudflare(tt.asn); got != tt.want {
				t.Errorf("IsCloudflare(%d) = %v, want %v", tt.asn, got, tt.want)
			}
		})
	}
}

func TestMarkCloudflare(t *testing.T) {
	results := []model.InfraResult{
		{IP: "104.16.0.1", ASN: 13335},
		{IP: "93.184.216.34", ASN: 15133},
		{IP: "104.16.0.2", ASN: 13335},
	}

	MarkCloudflare(results)

	if !results[0].IsCloudflare {
		t.Error("expected results[0] to be Cloudflare")
	}
	if results[1].IsCloudflare {
		t.Error("expected results[1] to not be Cloudflare")
	}
	if !results[2].IsCloudflare {
		t.Error("expected results[2] to be Cloudflare")
	}
}

func TestAnyCloudflare(t *testing.T) {
	tests := []struct {
		name    string
		results []model.InfraResult
		want    bool
	}{
		{
			name:    "has Cloudflare",
			results: []model.InfraResult{{ASN: 13335}, {ASN: 15169}},
			want:    true,
		},
		{
			name:    "no Cloudflare",
			results: []model.InfraResult{{ASN: 15169}, {ASN: 15133}},
			want:    false,
		},
		{
			name:    "empty results",
			results: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AnyCloudflare(tt.results); got != tt.want {
				t.Errorf("AnyCloudflare() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- BGP Parse Tests ---

func TestParseBGPUpstreams(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{
			name:  "standard upstreams",
			input: "ASN: AS13335\nUpstreams:    AS174, AS3356, AS6939\nDownstreams: AS12345\n",
			want:  []int{174, 3356, 6939},
		},
		{
			name:  "single upstream",
			input: "Upstreams:    AS174\n",
			want:  []int{174},
		},
		{
			name:  "no upstreams",
			input: "Upstreams:    None\n",
			want:  nil,
		},
		{
			name:  "empty response",
			input: "",
			want:  nil,
		},
		{
			name:  "no upstreams line",
			input: "ASN: AS13335\nName: Cloudflare\n",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := bufio.NewScanner(strings.NewReader(tt.input))
			got, err := ParseBGPUpstreams(scanner)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseBGPUpstreams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseBGPUpstreams() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseBGPUpstreams()[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// --- RDAP Tests ---

func TestLookupAbuseContact(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		network   *rdap.IPNetwork
		wantEmail string
		wantErr   bool
	}{
		{
			name: "abuse contact found",
			ip:   "93.184.216.34",
			network: &rdap.IPNetwork{
				Entities: []rdap.Entity{
					{
						Roles: []string{"abuse"},
						VCard: &rdap.VCard{
							Properties: []*rdap.VCardProperty{
								{Name: "fn", Type: "text", Value: "Abuse Team"},
								{Name: "email", Type: "text", Value: "abuse@example.com"},
							},
						},
					},
				},
			},
			wantEmail: "abuse@example.com",
		},
		{
			name: "nested abuse contact",
			ip:   "1.2.3.4",
			network: &rdap.IPNetwork{
				Entities: []rdap.Entity{
					{
						Roles: []string{"registrant"},
						Entities: []rdap.Entity{
							{
								Roles: []string{"abuse"},
								VCard: &rdap.VCard{
									Properties: []*rdap.VCardProperty{
										{Name: "email", Type: "text", Value: "nested-abuse@example.com"},
									},
								},
							},
						},
					},
				},
			},
			wantEmail: "nested-abuse@example.com",
		},
		{
			name: "no abuse role",
			ip:   "10.0.0.1",
			network: &rdap.IPNetwork{
				Entities: []rdap.Entity{
					{
						Roles: []string{"technical"},
						VCard: &rdap.VCard{
							Properties: []*rdap.VCardProperty{
								{Name: "email", Type: "text", Value: "tech@example.com"},
							},
						},
					},
				},
			},
			wantEmail: "",
		},
		{
			name:    "invalid IP",
			ip:      "not-an-ip",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockRDAPClient{
				results: map[string]*rdap.IPNetwork{},
			}
			if tt.network != nil {
				client.results[tt.ip] = tt.network
			}

			email, err := LookupAbuseContact(context.Background(), client, tt.ip)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LookupAbuseContact() error = %v, wantErr %v", err, tt.wantErr)
			}
			if email != tt.wantEmail {
				t.Errorf("LookupAbuseContact() = %q, want %q", email, tt.wantEmail)
			}
		})
	}
}

// --- Discovery Orchestrator Tests ---

func TestDiscoveryRun(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("93.184.216.0/24")
	_, cfPrefix, _ := net.ParseCIDR("104.16.0.0/24")

	tests := []struct {
		name           string
		domain         string
		ip4s           map[string][]net.IP
		ip6s           map[string][]net.IP
		asnResults     map[string]*ipisp.Response
		rdapResults    map[string]*rdap.IPNetwork
		bgpResults     map[int][]int
		wantCount      int
		wantCloudflare bool
		wantErr        bool
	}{
		{
			name:   "full pipeline single IP",
			domain: "example.com",
			ip4s: map[string][]net.IP{
				"example.com": {net.ParseIP("93.184.216.34")},
			},
			ip6s: map[string][]net.IP{},
			asnResults: map[string]*ipisp.Response{
				"93.184.216.34": {
					ASN:     15133,
					ISPName: "Edgecast Inc.",
					Range:   prefix,
					Country: "US",
				},
			},
			rdapResults: map[string]*rdap.IPNetwork{
				"93.184.216.34": {
					Entities: []rdap.Entity{
						{
							Roles: []string{"abuse"},
							VCard: &rdap.VCard{
								Properties: []*rdap.VCardProperty{
									{Name: "email", Type: "text", Value: "abuse@edgecast.com"},
								},
							},
						},
					},
				},
			},
			bgpResults: map[int][]int{
				15133: {174, 3356},
			},
			wantCount:      1,
			wantCloudflare: false,
		},
		{
			name:   "Cloudflare detected",
			domain: "cf-site.example.com",
			ip4s: map[string][]net.IP{
				"cf-site.example.com": {net.ParseIP("104.16.0.1")},
			},
			ip6s: map[string][]net.IP{},
			asnResults: map[string]*ipisp.Response{
				"104.16.0.1": {
					ASN:     13335,
					ISPName: "Cloudflare, Inc.",
					Range:   cfPrefix,
					Country: "US",
				},
			},
			rdapResults: map[string]*rdap.IPNetwork{
				"104.16.0.1": {},
			},
			bgpResults: map[int][]int{
				13335: {174, 3356, 6939},
			},
			wantCount:      1,
			wantCloudflare: true,
		},
		{
			name:   "multiple IPs with mixed ASNs",
			domain: "multi.example.com",
			ip4s: map[string][]net.IP{
				"multi.example.com": {
					net.ParseIP("93.184.216.34"),
					net.ParseIP("104.16.0.1"),
				},
			},
			ip6s: map[string][]net.IP{},
			asnResults: map[string]*ipisp.Response{
				"93.184.216.34": {
					ASN:     15133,
					ISPName: "Edgecast Inc.",
					Range:   prefix,
					Country: "US",
				},
				"104.16.0.1": {
					ASN:     13335,
					ISPName: "Cloudflare, Inc.",
					Range:   cfPrefix,
					Country: "US",
				},
			},
			rdapResults: map[string]*rdap.IPNetwork{
				"93.184.216.34": {},
				"104.16.0.1":    {},
			},
			bgpResults: map[int][]int{
				15133: {174},
				13335: {174, 3356},
			},
			wantCount:      2,
			wantCloudflare: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Discovery{
				DNS: &mockDNSResolver{
					ip4s: tt.ip4s,
					ip6s: tt.ip6s,
				},
				ASN: &mockASNClient{
					results: tt.asnResults,
				},
				RDAP: &mockRDAPClient{
					results: tt.rdapResults,
				},
				BGP: &mockBGPClient{
					results: tt.bgpResults,
				},
			}

			results, err := d.Run(context.Background(), tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Discovery.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(results) != tt.wantCount {
				t.Fatalf("Discovery.Run() got %d results, want %d", len(results), tt.wantCount)
			}
			if tt.wantCloudflare != AnyCloudflare(results) {
				t.Errorf("Discovery.Run() Cloudflare = %v, want %v", AnyCloudflare(results), tt.wantCloudflare)
			}
		})
	}
}

func TestDiscoveryRunFullPipeline(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("93.184.216.0/24")

	d := &Discovery{
		DNS: &mockDNSResolver{
			ip4s: map[string][]net.IP{
				"example.com": {net.ParseIP("93.184.216.34")},
			},
			ip6s: map[string][]net.IP{},
		},
		ASN: &mockASNClient{
			results: map[string]*ipisp.Response{
				"93.184.216.34": {
					ASN:     15133,
					ISPName: "Edgecast Inc.",
					Range:   prefix,
					Country: "US",
				},
			},
		},
		RDAP: &mockRDAPClient{
			results: map[string]*rdap.IPNetwork{
				"93.184.216.34": {
					Entities: []rdap.Entity{
						{
							Roles: []string{"abuse"},
							VCard: &rdap.VCard{
								Properties: []*rdap.VCardProperty{
									{Name: "email", Type: "text", Value: "abuse@edgecast.com"},
								},
							},
						},
					},
				},
			},
		},
		BGP: &mockBGPClient{
			results: map[int][]int{
				15133: {174, 3356},
			},
		},
	}

	results, err := d.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Discovery.Run() unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.IP != "93.184.216.34" {
		t.Errorf("IP = %q, want %q", r.IP, "93.184.216.34")
	}
	if r.RecordType != "A" {
		t.Errorf("RecordType = %q, want %q", r.RecordType, "A")
	}
	if r.ASN != 15133 {
		t.Errorf("ASN = %d, want %d", r.ASN, 15133)
	}
	if r.ASNName != "Edgecast Inc." {
		t.Errorf("ASNName = %q, want %q", r.ASNName, "Edgecast Inc.")
	}
	if r.Country != "US" {
		t.Errorf("Country = %q, want %q", r.Country, "US")
	}
	if r.AbuseContact != "abuse@edgecast.com" {
		t.Errorf("AbuseContact = %q, want %q", r.AbuseContact, "abuse@edgecast.com")
	}
	if r.IsCloudflare {
		t.Error("expected IsCloudflare = false")
	}
	if len(r.UpstreamASNs) != 2 || r.UpstreamASNs[0] != 174 || r.UpstreamASNs[1] != 3356 {
		t.Errorf("UpstreamASNs = %v, want [174 3356]", r.UpstreamASNs)
	}
}
