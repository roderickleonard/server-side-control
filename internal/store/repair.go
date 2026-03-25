package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var reverseProxyPassPattern = regexp.MustCompile(`(?m)proxy_pass\s+(https?://[^;\s]+);`)

func (s *Store) RepairManagedSiteUpstreams(ctx context.Context) (int64, error) {
	if s == nil {
		return 0, nil
	}

	rows, err := s.db.QueryContext(ctx, `SELECT name, nginx_config_path FROM managed_sites WHERE runtime = 'reverse_proxy' AND upstream_url = '' AND nginx_config_path <> ''`)
	if err != nil {
		return 0, fmt.Errorf("query managed sites for upstream repair: %w", err)
	}
	defer rows.Close()

	var repairedCount int64
	for rows.Next() {
		var name string
		var configPath string
		if err := rows.Scan(&name, &configPath); err != nil {
			return repairedCount, fmt.Errorf("scan managed site for upstream repair: %w", err)
		}

		upstreamURL, ok := extractUpstreamFromNginxConfig(configPath)
		if !ok {
			continue
		}

		result, err := s.db.ExecContext(ctx, `UPDATE managed_sites SET upstream_url = ? WHERE name = ?`, upstreamURL, name)
		if err != nil {
			return repairedCount, fmt.Errorf("update managed site upstream: %w", err)
		}
		if affected, err := result.RowsAffected(); err == nil {
			repairedCount += affected
		}
	}

	return repairedCount, rows.Err()
}

func extractUpstreamFromNginxConfig(configPath string) (string, bool) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" || !filepath.IsAbs(configPath) {
		return "", false
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", false
	}

	match := reverseProxyPassPattern.FindStringSubmatch(string(content))
	if len(match) < 2 {
		return "", false
	}
	return strings.TrimSpace(match[1]), true
}