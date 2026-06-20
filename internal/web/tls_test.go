package web

import (
	"reflect"
	"testing"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

func TestParseAdditionalDomains(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"www.example.com", []string{"www.example.com"}},
		{"www.example.com\napp.example.com", []string{"www.example.com", "app.example.com"}},
		{"www.example.com, app.example.com; api.example.com", []string{"www.example.com", "app.example.com", "api.example.com"}},
		{"  WWW.Example.com  ", []string{"www.example.com"}},
		{"a.com\na.com\nb.com", []string{"a.com", "b.com"}}, // dedupe
		{"", nil},
		{"   \n  , ;", nil},
	}
	for _, c := range cases {
		got := parseAdditionalDomains(c.in)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseAdditionalDomains(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSiteConfigPathForDomain(t *testing.T) {
	sites := []domain.ManagedSite{
		{DomainName: "example.com", NginxConfigPath: "/etc/nginx/sites-available/example.conf"},
		{DomainName: "Other.com", NginxConfigPath: "/etc/nginx/sites-available/other.conf"},
	}
	if got := siteConfigPathForDomain(sites, "example.com"); got != "/etc/nginx/sites-available/example.conf" {
		t.Errorf("exact match = %q", got)
	}
	if got := siteConfigPathForDomain(sites, "OTHER.com"); got != "/etc/nginx/sites-available/other.conf" {
		t.Errorf("case-insensitive match = %q", got)
	}
	if got := siteConfigPathForDomain(sites, "missing.com"); got != "" {
		t.Errorf("no match should be empty, got %q", got)
	}
	if got := siteConfigPathForDomain(sites, ""); got != "" {
		t.Errorf("empty domain should be empty, got %q", got)
	}
}
