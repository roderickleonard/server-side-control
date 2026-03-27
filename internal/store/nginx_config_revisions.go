package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

func (s *Store) CreateNginxConfigRevision(ctx context.Context, item domain.NginxConfigRevision) (int64, error) {
	if s == nil {
		return 0, errors.New("store is not configured")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO nginx_config_revisions (site_id, subdomain_id, config_path, content) VALUES (?, ?, ?, ?)`, item.SiteID, item.SubdomainID, item.ConfigPath, item.Content)
	if err != nil {
		return 0, fmt.Errorf("create nginx config revision: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read nginx config revision id: %w", err)
	}
	return id, nil
}

func (s *Store) ListNginxConfigRevisions(ctx context.Context, siteID int64, subdomainID int64, limit int) ([]domain.NginxConfigRevision, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, site_id, subdomain_id, config_path, content, created_at FROM nginx_config_revisions WHERE site_id = ? AND subdomain_id = ? ORDER BY id DESC LIMIT ?`, siteID, subdomainID, limit)
	if err != nil {
		return nil, fmt.Errorf("list nginx config revisions: %w", err)
	}
	defer rows.Close()
	items := make([]domain.NginxConfigRevision, 0, limit)
	for rows.Next() {
		var item domain.NginxConfigRevision
		if err := rows.Scan(&item.ID, &item.SiteID, &item.SubdomainID, &item.ConfigPath, &item.Content, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan nginx config revision: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetNginxConfigRevision(ctx context.Context, revisionID int64, siteID int64, subdomainID int64) (domain.NginxConfigRevision, error) {
	if s == nil {
		return domain.NginxConfigRevision{}, errors.New("store is not configured")
	}
	var item domain.NginxConfigRevision
	err := s.db.QueryRowContext(ctx, `SELECT id, site_id, subdomain_id, config_path, content, created_at FROM nginx_config_revisions WHERE id = ? AND site_id = ? AND subdomain_id = ? LIMIT 1`, revisionID, siteID, subdomainID).Scan(&item.ID, &item.SiteID, &item.SubdomainID, &item.ConfigPath, &item.Content, &item.CreatedAt)
	if err != nil {
		return domain.NginxConfigRevision{}, fmt.Errorf("get nginx config revision: %w", err)
	}
	return item, nil
}