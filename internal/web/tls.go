package web

import (
	"strings"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

// parseAdditionalDomains splits a free-text "additional domains" field into a
// clean, lower-cased domain slice. Names may be separated by newlines, commas,
// semicolons or whitespace.
func parseAdditionalDomains(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r', '\t', '\f', '\v', ' ':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

// siteConfigPathForDomain returns the nginx config path of the managed site
// whose primary domain matches domainName, or "" when no site matches. Used so
// the TLS flow can extend that config's server_name for multi-domain certs.
func siteConfigPathForDomain(sites []domain.ManagedSite, domainName string) string {
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	if domainName == "" {
		return ""
	}
	for _, s := range sites {
		if strings.ToLower(strings.TrimSpace(s.DomainName)) == domainName {
			return strings.TrimSpace(s.NginxConfigPath)
		}
	}
	return ""
}
