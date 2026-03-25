package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

func (s *Store) CreateAuditLog(ctx context.Context, entry domain.AuditLog) error {
	if s == nil {
		return errors.New("store is not configured")
	}

	metadata := "null"
	if entry.Metadata != "" {
		var raw json.RawMessage = json.RawMessage(entry.Metadata)
		if !json.Valid(raw) {
			return errors.New("audit metadata must be valid json")
		}
		metadata = entry.Metadata
	}

	query := `INSERT INTO audit_logs (actor, action, target, outcome, metadata) VALUES (?, ?, ?, ?, CAST(? AS JSON))`
	_, err := s.db.ExecContext(ctx, query, entry.Actor, entry.Action, entry.Target, entry.Outcome, metadata)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

func (s *Store) ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `SELECT id, actor, action, target, outcome, COALESCE(CAST(metadata AS CHAR), ''), created_at FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	logs := make([]domain.AuditLog, 0, limit)
	for rows.Next() {
		var entry domain.AuditLog
		if err := rows.Scan(&entry.ID, &entry.Actor, &entry.Action, &entry.Target, &entry.Outcome, &entry.Metadata, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, entry)
	}
	return logs, rows.Err()
}

func (s *Store) GetManagedSiteByName(ctx context.Context, name string) (domain.ManagedSite, error) {
	if s == nil {
		return domain.ManagedSite{}, errors.New("store is not configured")
	}

	var site domain.ManagedSite
	query := `SELECT id, name, owner_linux_user, domain_name, root_directory, runtime, upstream_url, php_version, nginx_config_path, created_at, updated_at FROM managed_sites WHERE name = ? LIMIT 1`
	if err := s.db.QueryRowContext(ctx, query, name).Scan(
		&site.ID,
		&site.Name,
		&site.OwnerLinuxUser,
		&site.DomainName,
		&site.RootDirectory,
		&site.Runtime,
		&site.UpstreamURL,
		&site.PHPVersion,
		&site.NginxConfigPath,
		&site.CreatedAt,
		&site.UpdatedAt,
	); err != nil {
		return domain.ManagedSite{}, err
	}
	return site, nil
}

func (s *Store) ListManagedSites(ctx context.Context) ([]domain.ManagedSite, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}

	rows, err := s.db.QueryContext(ctx, `SELECT id, name, owner_linux_user, domain_name, root_directory, runtime, upstream_url, php_version, nginx_config_path, created_at, updated_at FROM managed_sites ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list managed sites: %w", err)
	}
	defer rows.Close()

	sites := make([]domain.ManagedSite, 0)
	for rows.Next() {
		var site domain.ManagedSite
		if err := rows.Scan(
			&site.ID,
			&site.Name,
			&site.OwnerLinuxUser,
			&site.DomainName,
			&site.RootDirectory,
			&site.Runtime,
			&site.UpstreamURL,
			&site.PHPVersion,
			&site.NginxConfigPath,
			&site.CreatedAt,
			&site.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan managed site: %w", err)
		}
		sites = append(sites, site)
	}

	return sites, rows.Err()
}

func (s *Store) DeleteManagedSite(ctx context.Context, name string) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM managed_sites WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete managed site: %w", err)
	}
	return nil
}

func (s *Store) UpdateManagedSitePHPVersion(ctx context.Context, name string, version string) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE managed_sites SET php_version = ? WHERE name = ?`, version, name)
	if err != nil {
		return fmt.Errorf("update managed site php version: %w", err)
	}
	return nil
}
