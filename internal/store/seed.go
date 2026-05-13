package store

import (
	"context"
	"time"
)

// Seed inserts demo rows into the database. Safe to call multiple times —
// each INSERT is guarded by a NOT EXISTS check so existing rows are untouched.
func (s *Store) Seed(ctx context.Context) error {
	if s == nil {
		return nil
	}

	// --- managed_sites ---
	sites := []struct {
		name, owner, domain, root, runtime, upstream, php string
	}{
		{"demo-node", "www-data", "node.example.com", "/var/www/demo-node/public", "reverse_proxy", "127.0.0.1:3000", ""},
		{"demo-static", "www-data", "static.example.com", "/var/www/demo-static/public", "static", "", ""},
		{"demo-php", "www-data", "php.example.com", "/var/www/demo-php/public", "php", "", "8.2"},
	}
	for _, site := range sites {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO managed_sites
				(name, owner_linux_user, domain_name, root_directory, runtime, upstream_url, php_version, nginx_config_path)
			SELECT ?,?,?,?,?,?,?,''
			WHERE NOT EXISTS (SELECT 1 FROM managed_sites WHERE name = ?)
		`, site.name, site.owner, site.domain, site.root, site.runtime, site.upstream, site.php, site.name); err != nil {
			return err
		}
	}

	// --- audit_logs ---
	logs := []struct {
		actor, action, target, outcome string
		ts                             time.Time
	}{
		{"bootstrap", "site.create", "demo-node", "success", time.Now().Add(-72 * time.Hour)},
		{"bootstrap", "site.create", "demo-static", "success", time.Now().Add(-71 * time.Hour)},
		{"bootstrap", "site.create", "demo-php", "success", time.Now().Add(-70 * time.Hour)},
		{"bootstrap", "nginx.reload", "demo-node", "success", time.Now().Add(-48 * time.Hour)},
		{"bootstrap", "deploy.run", "demo-node", "success", time.Now().Add(-24 * time.Hour)},
	}
	for _, entry := range logs {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO audit_logs (actor, action, target, outcome, created_at)
			SELECT ?,?,?,?,?
			WHERE NOT EXISTS (
				SELECT 1 FROM audit_logs WHERE actor = ? AND action = ? AND target = ?
			)
		`, entry.actor, entry.action, entry.target, entry.outcome, entry.ts,
			entry.actor, entry.action, entry.target); err != nil {
			return err
		}
	}

	return nil
}
