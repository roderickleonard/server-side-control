package system

import (
	"regexp"
	"strings"
)

// serverNameDirective matches a single-line nginx "server_name ...;" directive,
// capturing its leading indentation and the space-separated name list.
var serverNameDirective = regexp.MustCompile(`(?m)^([ \t]*)server_name[ \t]+([^;{}]+);`)

// NormalizeTLSDomains returns the certificate's full domain list: the primary
// domain first, followed by the additional domains, lower-cased, trimmed and
// de-duplicated. Empty entries are dropped.
func NormalizeTLSDomains(primary string, additional []string) []string {
	seen := make(map[string]struct{}, len(additional)+1)
	out := make([]string, 0, len(additional)+1)
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	add(primary)
	for _, d := range additional {
		add(d)
	}
	return out
}

// AddServerNameAliases rewrites nginx config text so that every "server_name"
// directive which already lists `primary` also lists each alias in `aliases`.
// It is idempotent (never duplicates an existing name) and only touches server
// blocks that already serve the primary domain, so unrelated blocks are left
// alone. It returns the updated config and whether anything changed.
func AddServerNameAliases(config string, primary string, aliases []string) (string, bool) {
	primary = strings.ToLower(strings.TrimSpace(primary))
	if primary == "" || len(aliases) == 0 {
		return config, false
	}
	cleanAliases := make([]string, 0, len(aliases))
	for _, a := range aliases {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" && a != primary {
			cleanAliases = append(cleanAliases, a)
		}
	}
	if len(cleanAliases) == 0 {
		return config, false
	}

	changed := false
	out := serverNameDirective.ReplaceAllStringFunc(config, func(match string) string {
		m := serverNameDirective.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		indent := m[1]
		names := strings.Fields(m[2]) // original tokens; may be quoted

		// Membership is checked on unquoted, lower-cased names so that quoted
		// values like server_name "example.com"; are still recognised.
		existing := make(map[string]struct{}, len(names))
		hasPrimary := false
		for _, n := range names {
			key := strings.ToLower(strings.Trim(n, "\"'"))
			existing[key] = struct{}{}
			if key == primary {
				hasPrimary = true
			}
		}
		if !hasPrimary {
			return match
		}

		added := false
		for _, alias := range cleanAliases {
			if _, ok := existing[alias]; ok {
				continue
			}
			names = append(names, alias)
			existing[alias] = struct{}{}
			added = true
		}
		if !added {
			return match
		}
		changed = true
		return indent + "server_name " + strings.Join(names, " ") + ";"
	})
	return out, changed
}
