package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

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

	result, err := s.db.ExecContext(ctx, `UPDATE managed_sites SET owner_linux_user = ?, domain_name = ?, root_directory = ?, runtime = ?, php_version = ?, nginx_config_path = ? WHERE name = ?`,
		site.OwnerLinuxUser,
		site.DomainName,
		site.RootDirectory,
		site.Runtime,
		site.PHPVersion,
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
		runtime,
		php_version,
		nginx_config_path
	) VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		site.Name,
		site.OwnerLinuxUser,
		site.DomainName,
		site.RootDirectory,
		site.Runtime,
		site.PHPVersion,
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
