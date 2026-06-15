package system

import "testing"

func TestParseNginxServerBlocksReverseProxy(t *testing.T) {
	config := `
server {
    listen 80;
    listen [::]:80;
    server_name app.example.com www.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}
`
	blocks := ParseNginxServerBlocks(config)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 server block, got %d", len(blocks))
	}
	b := blocks[0]
	if len(b.Listens) != 2 {
		t.Fatalf("expected 2 listen directives, got %d", len(b.Listens))
	}
	for _, l := range b.Listens {
		if l.Port != "80" {
			t.Errorf("expected listen port 80, got %q", l.Port)
		}
		if l.SSL {
			t.Errorf("port 80 should not be SSL")
		}
	}
	if len(b.ServerNames) != 2 || b.ServerNames[0] != "app.example.com" || b.ServerNames[1] != "www.example.com" {
		t.Errorf("unexpected server names: %v", b.ServerNames)
	}
	if len(b.ProxyPasses) != 1 || b.ProxyPasses[0] != "http://127.0.0.1:3000" {
		t.Errorf("unexpected proxy passes: %v", b.ProxyPasses)
	}
}

func TestParseNginxServerBlocksTLSAndRedirect(t *testing.T) {
	config := `
server {
    listen 80;
    server_name panel.example.com;
    location / { return 308 https://$host$request_uri; }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl;
    server_name panel.example.com;
    ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
`
	blocks := ParseNginxServerBlocks(config)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 server blocks, got %d", len(blocks))
	}

	redirect := blocks[0]
	if len(redirect.Listens) != 1 || redirect.Listens[0].Port != "80" || redirect.Listens[0].SSL {
		t.Errorf("unexpected redirect listens: %v", redirect.Listens)
	}
	if len(redirect.ProxyPasses) != 0 {
		t.Errorf("redirect block should have no proxy_pass, got %v", redirect.ProxyPasses)
	}

	tls := blocks[1]
	if len(tls.Listens) != 2 {
		t.Fatalf("expected 2 TLS listens, got %d", len(tls.Listens))
	}
	for _, l := range tls.Listens {
		if l.Port != "443" {
			t.Errorf("expected port 443, got %q", l.Port)
		}
		if !l.SSL {
			t.Errorf("port 443 should be marked SSL")
		}
	}
	if len(tls.ProxyPasses) != 1 || tls.ProxyPasses[0] != "http://127.0.0.1:8080" {
		t.Errorf("unexpected TLS proxy passes: %v", tls.ProxyPasses)
	}
}

func TestParseNginxServerBlocksIgnoresCommentsAndUpstreamBlocks(t *testing.T) {
	config := `
# This whole server is disabled:
# server {
#     listen 9999;
#     server_name disabled.example.com;
# }

upstream backend_pool {
    server 127.0.0.1:5000;
    server 127.0.0.1:5001;
}

server {
    listen 127.0.0.1:8443 ssl; # custom local TLS port
    server_name internal.example.com;
    location / {
        proxy_pass http://backend_pool; # named upstream, no explicit port
    }
}
`
	blocks := ParseNginxServerBlocks(config)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 server block (commented + upstream ignored), got %d", len(blocks))
	}
	b := blocks[0]
	if len(b.Listens) != 1 || b.Listens[0].Port != "8443" || !b.Listens[0].SSL {
		t.Errorf("unexpected listens: %v", b.Listens)
	}
	if len(b.ProxyPasses) != 1 || b.ProxyPasses[0] != "http://backend_pool" {
		t.Errorf("unexpected proxy passes: %v", b.ProxyPasses)
	}
}

func TestParseNginxListenPort(t *testing.T) {
	cases := []struct {
		in       string
		wantPort string
		wantOK   bool
	}{
		{"80", "80", true},
		{"443", "443", true},
		{"[::]:80", "80", true},
		{"127.0.0.1:8080", "8080", true},
		{"*:8081", "8081", true},
		{"unix:/var/run/nginx.sock", "", false},
		{"", "", false},
		{"notaport", "", false},
		{"::1", "", false},        // bare IPv6 (invalid nginx syntax) must not yield "1"
		{"::", "", false},         // bare IPv6 unspecified address
		{"[::1]", "", false},      // bracketed IPv6 with no port
		{"[::1]:8080", "8080", true},
	}
	for _, c := range cases {
		port, ok := parseNginxListenPort(c.in)
		if port != c.wantPort || ok != c.wantOK {
			t.Errorf("parseNginxListenPort(%q) = (%q, %v), want (%q, %v)", c.in, port, ok, c.wantPort, c.wantOK)
		}
	}
}

func TestParseNginxServerBlocksEmpty(t *testing.T) {
	if blocks := ParseNginxServerBlocks(""); len(blocks) != 0 {
		t.Errorf("expected no blocks for empty config, got %d", len(blocks))
	}
}

func TestParseNginxServerBlocksPreservesHashInValue(t *testing.T) {
	// A '#' not preceded by whitespace is part of the value, not a comment, so
	// the directive (and its terminating ';') must survive comment stripping.
	config := `
server {
    listen 80;
    server_name app.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000/path#anchor;
    }
}
`
	blocks := ParseNginxServerBlocks(config)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 server block, got %d", len(blocks))
	}
	if len(blocks[0].ProxyPasses) != 1 || blocks[0].ProxyPasses[0] != "http://127.0.0.1:3000/path#anchor" {
		t.Errorf("unexpected proxy passes: %v", blocks[0].ProxyPasses)
	}
	if len(blocks[0].Listens) != 1 || blocks[0].Listens[0].Port != "80" {
		t.Errorf("unexpected listens: %v", blocks[0].Listens)
	}
}
