//go:build linux

package system

import (
	"strings"
	"testing"
)

func TestRenderNginxConfigReverseProxy(t *testing.T) {
	config := renderNginxConfig(SiteSpec{
		Domain:      "example.com",
		Mode:        "reverse_proxy",
		UpstreamURL: "127.0.0.1:3000",
	})

	if !strings.Contains(config, "proxy_pass http://127.0.0.1:3000;") {
		t.Fatalf("expected proxy_pass in config, got %q", config)
	}
}

func TestRenderNginxConfigTLS(t *testing.T) {
	config := renderTLSServerBlock("example.com")
	if !strings.Contains(config, "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;") {
		t.Fatalf("expected letsencrypt certificate path in tls config, got %q", config)
	}
}
