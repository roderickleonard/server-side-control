package web

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/kaganyegin/server-side-control/internal/system"
)

// PortProxy is one nginx proxy (a server block, or several server blocks for
// the same domain in the same file merged together) as shown on the Ports page.
type PortProxy struct {
	Domain       string   // primary server_name, or a placeholder when none
	Domains      []string // all server_name values for this proxy
	ListenPorts  []string // distinct listen ports, e.g. ["80", "443"]
	SSL          bool     // true when any listen directive terminates TLS
	Upstream     string   // proxy_pass target with the backend port (or first target)
	UpstreamPort string   // backend port extracted from Upstream, if explicit
	ConfigFile   string   // config file base name
	ConfigPath   string   // full config file path
}

// PortUsage summarises a single backend port and which domains forward to it.
type PortUsage struct {
	Port   string
	Owners []string
}

// nginxScanDirs returns the directories that are scanned for active nginx
// proxies: the panel's enabled-sites directory plus the conventional conf.d.
func (a *App) nginxScanDirs() []string {
	enabled := strings.TrimSpace(a.cfg.NginxEnabledDir)
	if enabled == "" {
		enabled = "/etc/nginx/sites-enabled"
	}
	dirs := []string{enabled}
	if confD := "/etc/nginx/conf.d"; confD != enabled {
		dirs = append(dirs, confD)
	}
	return dirs
}

func (a *App) handlePorts(w http.ResponseWriter, r *http.Request) {
	proxies, backendPorts, notices := a.collectNginxPortMap(r.Context())
	a.render(r.Context(), w, r.URL.Path, "ports.html", TemplateData{
		Title:            "Ports",
		DatabaseStatus:   a.databaseStatus(r.Context()),
		Metrics:          a.metrics.Snapshot(),
		PortProxies:      proxies,
		PortBackendPorts: backendPorts,
		PortScanNotices:  notices,
	})
}

// collectNginxPortMap scans every active nginx config it can read, parses the
// server blocks, and returns the per-proxy rows, the deduplicated backend-port
// summary, and any non-fatal notices (e.g. a directory that could not be read).
func (a *App) collectNginxPortMap(ctx context.Context) ([]PortProxy, []PortUsage, []string) {
	var notices []string
	// Merge server blocks that share a config file + primary domain so a
	// redirect block and its TLS counterpart show up as one row.
	merged := make(map[string]*PortProxy)
	var order []string

	if a.helper == nil {
		return nil, nil, []string{"The privileged helper is not configured, so nginx configs cannot be read."}
	}

	for _, dir := range a.nginxScanDirs() {
		var entries []helperSiteFileEntry
		if _, err := a.helper.Call(ctx, "files.list_dir", map[string]string{"path": dir}, &entries); err != nil {
			// A missing conf.d is normal; only surface unexpected read errors.
			if !strings.Contains(strings.ToLower(err.Error()), "no such file") {
				notices = append(notices, fmt.Sprintf("Could not list %s: %v", dir, err))
			}
			continue
		}
		for _, entry := range entries {
			if entry.IsDir {
				continue
			}
			name := strings.TrimSpace(entry.Name)
			if name == "" || strings.HasPrefix(name, ".") {
				continue
			}
			fullPath := filepath.Join(dir, name)
			var content string
			if _, err := a.helper.Call(ctx, "files.read_text", map[string]any{"path": fullPath, "max_bytes": 1048576}, &content); err != nil {
				// Best-effort: skip files we cannot read, but log it since the
				// helper runs as root and config files are normally readable.
				if a.logger != nil {
					a.logger.Warn("ports: could not read nginx config", "path", fullPath, "error", err)
				}
				continue
			}
			for _, block := range system.ParseNginxServerBlocks(content) {
				if len(block.Listens) == 0 && len(block.ProxyPasses) == 0 {
					continue
				}
				domains := dedupeStrings(block.ServerNames)
				primary := primaryDomain(domains)
				key := fullPath + "|" + primary
				proxy := merged[key]
				if proxy == nil {
					proxy = &PortProxy{
						Domain:     primary,
						ConfigFile: name,
						ConfigPath: fullPath,
					}
					merged[key] = proxy
					order = append(order, key)
				}
				proxy.Domains = dedupeStrings(append(proxy.Domains, domains...))
				for _, l := range block.Listens {
					proxy.ListenPorts = appendUniquePort(proxy.ListenPorts, l.Port)
					if l.SSL {
						proxy.SSL = true
					}
				}
				for _, target := range block.ProxyPasses {
					proxy.Upstream, proxy.UpstreamPort = chooseUpstream(proxy.Upstream, proxy.UpstreamPort, target)
				}
			}
		}
	}

	proxies := make([]PortProxy, 0, len(order))
	for _, key := range order {
		p := merged[key]
		sortPortStrings(p.ListenPorts)
		proxies = append(proxies, *p)
	}
	sort.SliceStable(proxies, func(i, j int) bool {
		return strings.ToLower(proxies[i].Domain) < strings.ToLower(proxies[j].Domain)
	})

	backendPorts := summarizeBackendPorts(proxies)
	return proxies, backendPorts, notices
}

// summarizeBackendPorts groups proxies by their backend (upstream) port.
func summarizeBackendPorts(proxies []PortProxy) []PortUsage {
	byPort := make(map[string][]string)
	var portOrder []string
	for _, p := range proxies {
		if p.UpstreamPort == "" {
			continue
		}
		if _, seen := byPort[p.UpstreamPort]; !seen {
			portOrder = append(portOrder, p.UpstreamPort)
		}
		byPort[p.UpstreamPort] = append(byPort[p.UpstreamPort], p.Domain)
	}
	usages := make([]PortUsage, 0, len(portOrder))
	for _, port := range portOrder {
		usages = append(usages, PortUsage{Port: port, Owners: dedupeStrings(byPort[port])})
	}
	sort.SliceStable(usages, func(i, j int) bool {
		return portLess(usages[i].Port, usages[j].Port)
	})
	return usages
}

// chooseUpstream folds one proxy_pass target into the running (upstream, port)
// selection across a proxy's server blocks: it locks onto the FIRST target that
// carries an explicit backend port (and prefers it for display), falling back
// to the first target overall when none carry a port. Once a port is chosen it
// is never overwritten by a later target.
func chooseUpstream(upstream, port, target string) (string, string) {
	if upstream == "" {
		upstream = target
	}
	if port == "" {
		if p := extractPortFromUpstream(target); p != "" {
			upstream = target
			port = p
		}
	}
	return upstream, port
}

func primaryDomain(domains []string) string {
	for _, d := range domains {
		if d != "" && d != "_" {
			return d
		}
	}
	if len(domains) > 0 {
		return domains[0] // "_" catch-all
	}
	return "(no server_name)"
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func appendUniquePort(ports []string, port string) []string {
	if port == "" {
		return ports
	}
	for _, p := range ports {
		if p == port {
			return ports
		}
	}
	return append(ports, port)
}

func sortPortStrings(ports []string) {
	sort.SliceStable(ports, func(i, j int) bool { return portLess(ports[i], ports[j]) })
}

// portLess orders ports numerically, falling back to lexical order when a value
// is not a number.
func portLess(a, b string) bool {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		return ai < bi
	}
	return a < b
}
