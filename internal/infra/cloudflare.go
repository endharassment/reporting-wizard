package infra

import "github.com/endharassment/reporting-wizard/internal/model"

// CloudflareASN is the primary ASN for Cloudflare.
const CloudflareASN = 13335

// IsCloudflare returns true if the given ASN belongs to Cloudflare.
func IsCloudflare(asn int) bool {
	return asn == CloudflareASN
}

// MarkCloudflare sets IsCloudflare on each InfraResult based on its ASN.
func MarkCloudflare(results []model.InfraResult) {
	for i := range results {
		results[i].IsCloudflare = IsCloudflare(results[i].ASN)
	}
}

// AnyCloudflare returns true if any result has a Cloudflare ASN.
func AnyCloudflare(results []model.InfraResult) bool {
	for _, r := range results {
		if IsCloudflare(r.ASN) {
			return true
		}
	}
	return false
}
