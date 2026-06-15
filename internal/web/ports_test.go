package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestPortsTemplateRenders(t *testing.T) {
	tmpl, err := parseTemplatesWithFuncs(templateFilesForPage("ports.html"))
	if err != nil {
		t.Fatalf("parse ports template: %v", err)
	}
	data := TemplateData{
		Title:       "Ports",
		CurrentPath: "/ports",
		AppName:     "Test Panel",
		Nav:         []NavItem{{Label: "Ports", Path: "/ports"}},
		PortProxies: []PortProxy{
			{
				Domain:       "app.example.com",
				Domains:      []string{"app.example.com", "www.app.example.com"},
				ListenPorts:  []string{"80", "443"},
				SSL:          true,
				Upstream:     "http://127.0.0.1:3000",
				UpstreamPort: "3000",
				ConfigFile:   "app.example.com.conf",
				ConfigPath:   "/etc/nginx/sites-enabled/app.example.com.conf",
			},
		},
		PortBackendPorts: []PortUsage{
			{Port: "3000", Owners: []string{"app.example.com"}},
		},
		PortScanNotices: []string{"Could not list /etc/nginx/conf.d: boom"},
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute ports template: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"app.example.com", "3000", "Backend ports in use", "All nginx proxies"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered ports page missing %q", want)
		}
	}
}

func TestSummarizeBackendPorts(t *testing.T) {
	proxies := []PortProxy{
		{Domain: "b.example.com", UpstreamPort: "3000"},
		{Domain: "a.example.com", UpstreamPort: "8080"},
		{Domain: "c.example.com", UpstreamPort: "3000"},
		{Domain: "d.example.com", UpstreamPort: ""}, // static site, no backend
	}
	usages := summarizeBackendPorts(proxies)
	if len(usages) != 2 {
		t.Fatalf("expected 2 distinct backend ports, got %d (%v)", len(usages), usages)
	}
	// Sorted numerically: 3000 before 8080.
	if usages[0].Port != "3000" || usages[1].Port != "8080" {
		t.Fatalf("unexpected port order: %v", usages)
	}
	if len(usages[0].Owners) != 2 {
		t.Errorf("expected port 3000 to have 2 owners, got %v", usages[0].Owners)
	}
}

func TestPrimaryDomain(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"example.com", "www.example.com"}, "example.com"},
		{[]string{"_", "fallback.example.com"}, "fallback.example.com"},
		{[]string{"_"}, "_"},
		{nil, "(no server_name)"},
	}
	for _, c := range cases {
		if got := primaryDomain(c.in); got != c.want {
			t.Errorf("primaryDomain(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestChooseUpstreamPrefersFirstWithPort(t *testing.T) {
	// Simulate folding several proxy_pass targets (e.g. across location blocks)
	// into one proxy. The FIRST target with an explicit port must win.
	upstream, port := "", ""
	for _, target := range []string{"http://named_pool", "http://127.0.0.1:3000", "http://127.0.0.1:5000"} {
		upstream, port = chooseUpstream(upstream, port, target)
	}
	if port != "3000" {
		t.Errorf("expected first explicit port 3000, got %q", port)
	}
	if upstream != "http://127.0.0.1:3000" {
		t.Errorf("expected upstream to match the port-bearing target, got %q", upstream)
	}
}

func TestChooseUpstreamFallsBackToFirstTarget(t *testing.T) {
	// When no target carries an explicit port, the first target is shown and no
	// backend port is reported.
	upstream, port := chooseUpstream("", "", "http://named_pool")
	if upstream != "http://named_pool" || port != "" {
		t.Errorf("chooseUpstream named-only = (%q, %q), want (http://named_pool, \"\")", upstream, port)
	}
}

func TestSortPortStrings(t *testing.T) {
	ports := []string{"443", "80", "8080", "3000"}
	sortPortStrings(ports)
	want := []string{"80", "443", "3000", "8080"}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("sortPortStrings = %v, want %v", ports, want)
		}
	}
}
