package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

// UsedPort describes a reverse-proxy upstream port already allocated to a site or subdomain.
type UsedPort struct {
	Port  string
	Owner string // site name or subdomain full domain
}

// ListUsedPorts returns every port currently referenced by a reverse-proxy site or subdomain.
func (s *Store) ListUsedPorts(ctx context.Context) ([]UsedPort, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, upstream_url FROM managed_sites
		WHERE runtime = 'reverse_proxy' AND upstream_url != ''
		UNION ALL
		SELECT full_domain, upstream_url FROM site_subdomains
		WHERE runtime = 'reverse_proxy' AND upstream_url != ''
	`)
	if err != nil {
		return nil, fmt.Errorf("list used ports: %w", err)
	}
	defer rows.Close()
	var result []UsedPort
	for rows.Next() {
		var owner, upstream string
		if err := rows.Scan(&owner, &upstream); err != nil {
			continue
		}
		if port := upstreamPort(upstream); port != "" {
			result = append(result, UsedPort{Port: port, Owner: owner})
		}
	}
	return result, nil
}

// upstreamPort extracts the port number from an upstream URL such as
// "127.0.0.1:3000", "http://127.0.0.1:3000", or "https://example.com:8443".
func upstreamPort(upstream string) string {
	s := upstream
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return ""
	}
	return port
}

var mysqlNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

var ErrInvalidDatabaseName = errors.New("invalid mysql database name")
var ErrInvalidUserName = errors.New("invalid mysql user name")

func (s *Store) ProvisionDatabase(ctx context.Context, databaseName string, username string, password string) error {
	if s == nil {
		return errors.New("store is not configured")
	}

	databaseName = strings.TrimSpace(databaseName)
	username = strings.TrimSpace(username)
	if !mysqlNamePattern.MatchString(databaseName) {
		return ErrInvalidDatabaseName
	}
	if !mysqlNamePattern.MatchString(username) {
		return ErrInvalidUserName
	}

	statements := []string{
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", quoteIdentifier(databaseName)),
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s@'%%' IDENTIFIED BY %s", quoteIdentifier(username), quoteString(password)),
		fmt.Sprintf("ALTER USER %s@'%%' IDENTIFIED BY %s", quoteIdentifier(username), quoteString(password)),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO %s@'%%'", quoteIdentifier(databaseName), quoteIdentifier(username)),
		"FLUSH PRIVILEGES",
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("mysql provision statement failed: %w", err)
		}
	}

	return nil
}

func quoteIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "") + "`"
}

func quoteString(value string) string {
	replacer := strings.NewReplacer(`\\`, `\\\\`, `'`, `\\'`)
	return "'" + replacer.Replace(value) + "'"
}

func (s *Store) CreateManagedSite(ctx context.Context, site domain.ManagedSite) error {
	if s == nil {
		return errors.New("store is not configured")
	}

	result, err := s.db.ExecContext(ctx, `UPDATE managed_sites SET owner_linux_user = ?, domain_name = ?, root_directory = ?, laravel_extra_writable_paths = ?, runtime = ?, upstream_url = ?, php_version = ?, node_version = ?, nginx_config_path = ? WHERE name = ?`,
		site.OwnerLinuxUser,
		site.DomainName,
		site.RootDirectory,
		site.LaravelExtraWritablePaths,
		site.Runtime,
		site.UpstreamURL,
		site.PHPVersion,
		site.NodeVersion,
		site.NginxConfigPath,
		site.Name,
	)
	if err != nil {
		return fmt.Errorf("update managed site: %w", err)
	}
	if rowsAffected, rowsErr := result.RowsAffected(); rowsErr == nil && rowsAffected > 0 {
		return nil
	}

	query := `INSERT INTO managed_sites (
		name,
		owner_linux_user,
		domain_name,
		root_directory,
		laravel_extra_writable_paths,
		runtime,
		upstream_url,
		php_version,
		node_version,
		auto_deploy_enabled,
		auto_deploy_branch,
		auto_deploy_secret,
		auto_deploy_command,
		auto_deploy_node_version,
		auto_deploy_notify_email,
		nginx_config_path
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		site.Name,
		site.OwnerLinuxUser,
		site.DomainName,
		site.RootDirectory,
		site.LaravelExtraWritablePaths,
		site.Runtime,
		site.UpstreamURL,
		site.PHPVersion,
		site.NodeVersion,
		site.AutoDeployEnabled,
		site.AutoDeployBranch,
		site.AutoDeploySecret,
		site.AutoDeployCommand,
		site.AutoDeployNodeVersion,
		site.AutoDeployNotifyEmail,
		site.NginxConfigPath,
	)
	if err != nil {
		return fmt.Errorf("insert managed site: %w", err)
	}
	return nil
}

func (s *Store) CreateDeployment(ctx context.Context, deployment domain.Deployment) error {
	if s == nil {
		return errors.New("store is not configured")
	}

	query := `INSERT INTO deployments (
		repository_url,
		branch_name,
		target_directory,
		run_as_user,
		last_status,
		last_output
	) VALUES (?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		deployment.RepositoryURL,
		deployment.BranchName,
		deployment.TargetDirectory,
		deployment.RunAsUser,
		deployment.LastStatus,
		deployment.LastOutput,
	)
	if err != nil {
		return fmt.Errorf("insert deployment: %w", err)
	}
	return nil
}
