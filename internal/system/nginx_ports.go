package system

import (
	"strconv"
	"strings"
)

// NginxListen describes a single nginx "listen" directive: the port it binds
// and whether it terminates TLS.
type NginxListen struct {
	Port string
	SSL  bool
}

// NginxServerBlock is a parsed nginx "server { ... }" block, capturing only the
// directives relevant to a port/proxy overview.
type NginxServerBlock struct {
	ServerNames []string
	Listens     []NginxListen
	ProxyPasses []string
}

// ParseNginxServerBlocks parses nginx configuration text and returns every
// "server" block it contains, extracting listen ports, server_name values and
// proxy_pass upstreams. It tolerates nested location blocks and comments. It is
// intended for read-only inspection of which ports are in use, not for full
// nginx config validation.
func ParseNginxServerBlocks(config string) []NginxServerBlock {
	tokens := tokenizeNginxConfig(stripNginxComments(config))

	var blocks []NginxServerBlock

	// stack mirrors the current brace nesting. Each frame records whether the
	// block it opened was a "server" block and, if so, its index in blocks.
	type frame struct {
		isServer bool
		index    int
	}
	var stack []frame
	var words []string

	enclosingServerIndex := func() int {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].isServer {
				return stack[i].index
			}
		}
		return -1
	}

	for _, tok := range tokens {
		switch tok {
		case "{":
			isServer := len(words) > 0 && words[0] == "server"
			f := frame{isServer: isServer, index: -1}
			if isServer {
				blocks = append(blocks, NginxServerBlock{})
				f.index = len(blocks) - 1
			}
			stack = append(stack, f)
			words = nil
		case "}":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			words = nil
		case ";":
			if len(words) > 0 {
				if idx := enclosingServerIndex(); idx >= 0 {
					applyNginxDirective(&blocks[idx], words)
				}
			}
			words = nil
		default:
			words = append(words, tok)
		}
	}

	return blocks
}

// applyNginxDirective records a single directive (already split into words) on
// the server block it belongs to. Only listen, server_name and proxy_pass are
// relevant for the ports overview; everything else is ignored.
func applyNginxDirective(block *NginxServerBlock, words []string) {
	switch words[0] {
	case "listen":
		if len(words) < 2 {
			return
		}
		port, ok := parseNginxListenPort(words[1])
		if !ok {
			return
		}
		ssl := false
		for _, w := range words[2:] {
			if w == "ssl" {
				ssl = true
				break
			}
		}
		block.Listens = append(block.Listens, NginxListen{Port: port, SSL: ssl})
	case "server_name":
		for _, name := range words[1:] {
			name = strings.Trim(name, "\"'")
			if name != "" {
				block.ServerNames = append(block.ServerNames, name)
			}
		}
	case "proxy_pass":
		if len(words) >= 2 {
			block.ProxyPasses = append(block.ProxyPasses, words[1])
		}
	}
}

// parseNginxListenPort extracts the port from a listen directive's address
// argument, handling forms like "80", "443", "[::]:80", "127.0.0.1:8080" and
// "*:80". It returns ("", false) for forms without a numeric port (e.g. unix
// sockets).
func parseNginxListenPort(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.HasPrefix(spec, "unix:") {
		return "", false
	}
	if i := strings.LastIndex(spec, "]:"); i >= 0 {
		// IPv6 form with port: [::]:443
		spec = spec[i+2:]
	} else if strings.HasPrefix(spec, "[") {
		// Bracketed IPv6 with no port, e.g. "[::1]" — not a port spec.
		return "", false
	} else if strings.Count(spec, ":") > 1 {
		// Bare IPv6 such as "::1" is invalid nginx listen syntax (it must be
		// bracketed); don't mistake its trailing segment for a port.
		return "", false
	} else if i := strings.LastIndexByte(spec, ':'); i >= 0 {
		// host:port form: 127.0.0.1:8080 or *:80
		spec = spec[i+1:]
	}
	if spec == "" {
		return "", false
	}
	if _, err := strconv.Atoi(spec); err != nil {
		return "", false
	}
	return spec, true
}

// tokenizeNginxConfig splits nginx config text into a flat token stream where
// the structural characters '{', '}' and ';' are individual tokens and all
// other runs of non-whitespace are word tokens.
func tokenizeNginxConfig(s string) []string {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '{', '}', ';':
			flush()
			tokens = append(tokens, string(r))
		case ' ', '\t', '\n', '\r', '\f', '\v':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return tokens
}

// stripNginxComments removes "#" comments (from the '#' to end of line) so the
// tokenizer does not treat commented-out directives as live ones.
func stripNginxComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		// Treat '#' as a comment marker only at the start of a line or when
		// preceded by whitespace, so a '#' inside a directive value (e.g. a URL
		// or quoted string) is preserved rather than truncating the directive.
		for i := 0; i < len(line); i++ {
			if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				line = line[:i]
				break
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
