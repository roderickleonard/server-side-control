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

func TestRenderPanelProxyConfigWithoutTLS(t *testing.T) {
	config := renderPanelProxyConfig("example.com", "127.0.0.1:8080", "", "")
	if !strings.Contains(config, "listen 80;") {
		t.Fatalf("expected http listener in config, got %q", config)
	}
	if strings.Contains(config, "listen 443 ssl;") {
		t.Fatalf("did not expect tls listener without certificate, got %q", config)
	}
	if !strings.Contains(config, "proxy_pass http://127.0.0.1:8080;") {
		t.Fatalf("expected panel upstream in config, got %q", config)
	}
}

func TestRenderPanelProxyConfigWithTLS(t *testing.T) {
	config := renderPanelProxyConfig("example.com", "127.0.0.1:8080", "/etc/letsencrypt/live/example.com/fullchain.pem", "/etc/letsencrypt/live/example.com/privkey.pem")
	if !strings.Contains(config, "listen 443 ssl;") {
		t.Fatalf("expected tls listener in config, got %q", config)
	}
	if !strings.Contains(config, "return 308 https://$host$request_uri;") {
		t.Fatalf("expected http to https redirect in config, got %q", config)
	}
	if !strings.Contains(config, "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;") {
		t.Fatalf("expected tls certificate path in config, got %q", config)
	}
	if !strings.Contains(config, "proxy_pass http://127.0.0.1:8080;") {
		t.Fatalf("expected panel upstream in tls config, got %q", config)
	}
}
