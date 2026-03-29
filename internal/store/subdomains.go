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
	rows, err := s.db.QueryContext(ctx, `SELECT id, site_id, subdomain, full_domain, runtime, upstream_url, php_version, repository_url, branch_name, git_credential_protocol, git_credential_username, post_deploy_command, auto_deploy_enabled, auto_deploy_branch, auto_deploy_secret, auto_deploy_command, auto_deploy_notify_email, root_directory, nginx_config_path, created_at, updated_at FROM site_subdomains WHERE site_id = ? ORDER BY full_domain ASC`, siteID)
	if err != nil {
		return nil, fmt.Errorf("list site subdomains: %w", err)
	}
	defer rows.Close()
	items := make([]domain.SiteSubdomain, 0)
	for rows.Next() {
		var item domain.SiteSubdomain
		if err := rows.Scan(&item.ID, &item.SiteID, &item.Subdomain, &item.FullDomain, &item.Runtime, &item.UpstreamURL, &item.PHPVersion, &item.RepositoryURL, &item.BranchName, &item.GitCredentialProtocol, &item.GitCredentialUsername, &item.PostDeployCommand, &item.AutoDeployEnabled, &item.AutoDeployBranch, &item.AutoDeploySecret, &item.AutoDeployCommand, &item.AutoDeployNotifyEmail, &item.RootDirectory, &item.NginxConfigPath, &item.CreatedAt, &item.UpdatedAt); err != nil {
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO site_subdomains (site_id, subdomain, full_domain, runtime, upstream_url, php_version, repository_url, branch_name, git_credential_protocol, git_credential_username, post_deploy_command, auto_deploy_enabled, auto_deploy_branch, auto_deploy_secret, auto_deploy_command, auto_deploy_notify_email, root_directory, nginx_config_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, item.SiteID, item.Subdomain, item.FullDomain, item.Runtime, item.UpstreamURL, item.PHPVersion, item.RepositoryURL, item.BranchName, item.GitCredentialProtocol, item.GitCredentialUsername, item.PostDeployCommand, item.AutoDeployEnabled, item.AutoDeployBranch, item.AutoDeploySecret, item.AutoDeployCommand, item.AutoDeployNotifyEmail, item.RootDirectory, item.NginxConfigPath)
	if err != nil {
		return fmt.Errorf("create site subdomain: %w", err)
	}
	return nil
}

func (s *Store) UpdateSiteSubdomainDeploy(ctx context.Context, siteID int64, subdomainID int64, repositoryURL string, branchName string, postDeployCommand string, enabled bool, autoDeployBranch string, autoDeploySecret string, autoDeployCommand string, autoDeployNotifyEmail string) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE site_subdomains SET repository_url = ?, branch_name = ?, post_deploy_command = ?, auto_deploy_enabled = ?, auto_deploy_branch = ?, auto_deploy_secret = ?, auto_deploy_command = ?, auto_deploy_notify_email = ? WHERE site_id = ? AND id = ?`, repositoryURL, branchName, postDeployCommand, enabled, autoDeployBranch, autoDeploySecret, autoDeployCommand, autoDeployNotifyEmail, siteID, subdomainID)
	if err != nil {
		return fmt.Errorf("update site subdomain deploy: %w", err)
	}
	return nil
}

func (s *Store) UpdateSiteSubdomainLocation(ctx context.Context, siteID int64, subdomainID int64, rootDirectory string, nginxConfigPath string) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE site_subdomains SET root_directory = ?, nginx_config_path = ? WHERE site_id = ? AND id = ?`, rootDirectory, nginxConfigPath, siteID, subdomainID)
	if err != nil {
		return fmt.Errorf("update site subdomain location: %w", err)
	}
	return nil
}

func (s *Store) UpdateSiteSubdomainGitCredentialPreferences(ctx context.Context, siteID int64, subdomainID int64, protocol string, username string) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE site_subdomains SET git_credential_protocol = ?, git_credential_username = ? WHERE site_id = ? AND id = ?`, protocol, username, siteID, subdomainID)
	if err != nil {
		return fmt.Errorf("update site subdomain git credential preferences: %w", err)
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