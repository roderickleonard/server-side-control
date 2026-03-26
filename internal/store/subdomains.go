package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

func (s *Store) ListSiteSubdomains(ctx context.Context, siteID int64) ([]domain.SiteSubdomain, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, site_id, subdomain, full_domain, runtime, upstream_url, php_version, root_directory, nginx_config_path, created_at, updated_at FROM site_subdomains WHERE site_id = ? ORDER BY full_domain ASC`, siteID)
	if err != nil {
		return nil, fmt.Errorf("list site subdomains: %w", err)
	}
	defer rows.Close()
	items := make([]domain.SiteSubdomain, 0)
	for rows.Next() {
		var item domain.SiteSubdomain
		if err := rows.Scan(&item.ID, &item.SiteID, &item.Subdomain, &item.FullDomain, &item.Runtime, &item.UpstreamURL, &item.PHPVersion, &item.RootDirectory, &item.NginxConfigPath, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan site subdomain: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CreateSiteSubdomain(ctx context.Context, item domain.SiteSubdomain) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO site_subdomains (site_id, subdomain, full_domain, runtime, upstream_url, php_version, root_directory, nginx_config_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, item.SiteID, item.Subdomain, item.FullDomain, item.Runtime, item.UpstreamURL, item.PHPVersion, item.RootDirectory, item.NginxConfigPath)
	if err != nil {
		return fmt.Errorf("create site subdomain: %w", err)
	}
	return nil
}

func (s *Store) DeleteSiteSubdomain(ctx context.Context, siteID int64, subdomainID int64) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM site_subdomains WHERE site_id = ? AND id = ?`, siteID, subdomainID)
	if err != nil {
		return fmt.Errorf("delete site subdomain: %w", err)
	}
	return nil
}