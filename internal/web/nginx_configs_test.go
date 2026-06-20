package web

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestNginxServerNamesIn(t *testing.T) {
	config := `server {
    listen 80;
    server_name ohannesburger.com www.ohannesburger.com;
    location / { proxy_pass http://127.0.0.1:3200; }
}
server {
    listen 443 ssl;
    server_name _;
}
`
	got := nginxServerNamesIn(config)
	want := []string{"ohannesburger.com", "www.ohannesburger.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nginxServerNamesIn = %v, want %v (catch-all _ excluded, deduped)", got, want)
	}
}

func TestNginxConfigsTemplateRenders(t *testing.T) {
	tmpl, err := parseTemplatesWithFuncs(templateFilesForPage("nginx_configs.html"))
	if err != nil {
		t.Fatalf("parse nginx_configs template: %v", err)
	}
	data := TemplateData{
		Title:       "Nginx",
		CurrentPath: "/nginx",
		AppName:     "Test Panel",
		Nav:         []NavItem{{Label: "Nginx", Path: "/nginx"}},
		NginxConfigFiles: []NginxConfigFile{
			{Name: "default", Path: "/etc/nginx/sites-available/default", Enabled: true, Domains: []string{"www.ohannesburger.com"}, Managed: ""},
			{Name: "ohannes-main.conf", Path: "/etc/nginx/sites-available/ohannes-main.conf", Enabled: true, Domains: []string{"ohannesburger.com", "www.ohannesburger.com"}, Managed: "ohannes"},
		},
		NginxEditName:    "default",
		NginxEditContent: "server { server_name www.ohannesburger.com; root /var/www/html; }",
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatalf("execute nginx_configs template: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"default", "Editing default", "Disable", "site: ohannes", "Config files"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered nginx configs page missing %q", want)
		}
	}
}
