package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Store struct {
	db *sql.DB
}

func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func Open(dsn string) (*Store, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping mysql: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) Migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	sort.Slice(entries, func(i int, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		sqlBytes, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		for _, statement := range splitStatements(string(sqlBytes)) {
			if statement == "" {
				continue
			}
			if _, err := s.db.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
			}
		}
	}

	if err := s.ensureManagedSitesUpstreamColumn(ctx); err != nil {
		return fmt.Errorf("ensure managed_sites.upstream_url column: %w", err)
	}

	if err := s.ensureManagedSitesDatabaseColumn(ctx); err != nil {
		return fmt.Errorf("ensure managed_sites.database_name column: %w", err)
	}

	if err := s.ensureManagedSitesAutoDeployColumns(ctx); err != nil {
		return fmt.Errorf("ensure managed_sites auto deploy columns: %w", err)
	}

	if err := s.ensureManagedSitesNodeVersionColumn(ctx); err != nil {
		return fmt.Errorf("ensure managed_sites node version column: %w", err)
	}

	if err := s.ensureManagedSitesLaravelPathsColumn(ctx); err != nil {
		return fmt.Errorf("ensure managed_sites laravel extra writable paths column: %w", err)
	}

	if err := s.ensureManagedSitesRoute53Columns(ctx); err != nil {
		return fmt.Errorf("ensure managed_sites route53 columns: %w", err)
	}

	if err := s.ensureManagedSitesBackupColumns(ctx); err != nil {
		return fmt.Errorf("ensure managed_sites backup columns: %w", err)
	}

	if err := s.ensureSiteBackupsTable(ctx); err != nil {
		return fmt.Errorf("ensure site_backups table: %w", err)
	}

	if err := s.ensureSiteRuntimeCommandsTable(ctx); err != nil {
		return fmt.Errorf("ensure site_runtime_commands table: %w", err)
	}

	if err := s.ensureSiteSubdomainsTable(ctx); err != nil {
		return fmt.Errorf("ensure site_subdomains table: %w", err)
	}

	if err := s.ensureSubdomainRuntimeCommandsTable(ctx); err != nil {
		return fmt.Errorf("ensure subdomain_runtime_commands table: %w", err)
	}

	if err := s.ensureSiteSubdomainsDeployColumns(ctx); err != nil {
		return fmt.Errorf("ensure site_subdomains deploy columns: %w", err)
	}

	if err := s.ensureSiteSubdomainsNodeVersionColumn(ctx); err != nil {
		return fmt.Errorf("ensure site_subdomains node version column: %w", err)
	}

	if err := s.ensureSiteSubdomainsLaravelPathsColumn(ctx); err != nil {
		return fmt.Errorf("ensure site_subdomains laravel extra writable paths column: %w", err)
	}

	if err := s.ensureNginxConfigRevisionsTable(ctx); err != nil {
		return fmt.Errorf("ensure nginx_config_revisions table: %w", err)
	}

	if err := s.ensurePanelUsersTOTPColumns(ctx); err != nil {
		return fmt.Errorf("ensure panel_users totp columns: %w", err)
	}

	if err := s.ensurePanelUsersRecoveryColumns(ctx); err != nil {
		return fmt.Errorf("ensure panel_users recovery columns: %w", err)
	}

	if err := s.ensurePanelUserPasskeysTable(ctx); err != nil {
		return fmt.Errorf("ensure panel_user_passkeys table: %w", err)
	}

	return nil
}

func (s *Store) ensurePanelUsersTOTPColumns(ctx context.Context) error {
	if s == nil {
		return nil
	}
	columns := []struct {
		name      string
		statement string
	}{
		{name: "totp_enabled", statement: `ALTER TABLE panel_users ADD COLUMN totp_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER enabled`},
		{name: "totp_secret", statement: `ALTER TABLE panel_users ADD COLUMN totp_secret VARCHAR(128) NOT NULL DEFAULT '' AFTER totp_enabled`},
		{name: "totp_enabled_at", statement: `ALTER TABLE panel_users ADD COLUMN totp_enabled_at DATETIME NULL AFTER totp_secret`},
	}
	for _, column := range columns {
		var count int
		err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = DATABASE()
			  AND table_name = 'panel_users'
			  AND column_name = ?
		`, column.name).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.statement); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *Store) ensurePanelUsersRecoveryColumns(ctx context.Context) error {
	if s == nil {
		return nil
	}
	columns := []struct {
		name      string
		statement string
	}{
		{name: "recovery_codes_json", statement: `ALTER TABLE panel_users ADD COLUMN recovery_codes_json MEDIUMTEXT NOT NULL DEFAULT ('[]') AFTER totp_enabled_at`},
		{name: "recovery_generated_at", statement: `ALTER TABLE panel_users ADD COLUMN recovery_generated_at DATETIME NULL AFTER recovery_codes_json`},
	}
	for _, column := range columns {
		var count int
		err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = DATABASE()
			  AND table_name = 'panel_users'
			  AND column_name = ?
		`, column.name).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.statement); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE panel_users SET recovery_codes_json = '[]' WHERE recovery_codes_json IS NULL OR recovery_codes_json = ''`); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensurePanelUserPasskeysTable(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS panel_user_passkeys (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			linux_user VARCHAR(191) NOT NULL,
			credential_id VARCHAR(512) NOT NULL,
			label VARCHAR(191) NOT NULL DEFAULT '',
			public_key_spki TEXT NOT NULL,
			sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			UNIQUE KEY uniq_panel_user_passkeys_credential_id (credential_id),
			INDEX idx_panel_user_passkeys_linux_user (linux_user)
		)`)
	return err
}

func (s *Store) ensureManagedSitesUpstreamColumn(ctx context.Context) error {
	if s == nil {
		return nil
	}

	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'managed_sites'
		  AND column_name = 'upstream_url'
	`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	_, err = s.db.ExecContext(ctx, `ALTER TABLE managed_sites ADD COLUMN upstream_url VARCHAR(255) NOT NULL DEFAULT '' AFTER runtime`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) ensureManagedSitesDatabaseColumn(ctx context.Context) error {
	if s == nil {
		return nil
	}

	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'managed_sites'
		  AND column_name = 'database_name'
	`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	_, err = s.db.ExecContext(ctx, `ALTER TABLE managed_sites ADD COLUMN database_name VARCHAR(191) NOT NULL DEFAULT '' AFTER php_version`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) ensureSiteRuntimeCommandsTable(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS site_runtime_commands (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			site_id BIGINT NOT NULL,
			name VARCHAR(191) NOT NULL,
			command_body TEXT NOT NULL,
			node_version VARCHAR(64) NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_site_runtime_commands_site_id (site_id),
			CONSTRAINT fk_site_runtime_commands_site FOREIGN KEY (site_id) REFERENCES managed_sites(id) ON DELETE CASCADE
		)`)
	return err
}

func (s *Store) ensureSubdomainRuntimeCommandsTable(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS subdomain_runtime_commands (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			subdomain_id BIGINT NOT NULL,
			name VARCHAR(191) NOT NULL,
			command_body TEXT NOT NULL,
			node_version VARCHAR(64) NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_subdomain_runtime_commands_subdomain_id (subdomain_id),
			CONSTRAINT fk_subdomain_runtime_commands_subdomain FOREIGN KEY (subdomain_id) REFERENCES site_subdomains(id) ON DELETE CASCADE
		)`)
	return err
}

func (s *Store) ensureManagedSitesAutoDeployColumns(ctx context.Context) error {
	if s == nil {
		return nil
	}
	columns := []struct {
		name      string
		statement string
	}{
		{name: "auto_deploy_enabled", statement: `ALTER TABLE managed_sites ADD COLUMN auto_deploy_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER database_name`},
		{name: "auto_deploy_branch", statement: `ALTER TABLE managed_sites ADD COLUMN auto_deploy_branch VARCHAR(191) NOT NULL DEFAULT '' AFTER auto_deploy_enabled`},
		{name: "auto_deploy_secret", statement: `ALTER TABLE managed_sites ADD COLUMN auto_deploy_secret VARCHAR(255) NOT NULL DEFAULT '' AFTER auto_deploy_branch`},
		{name: "auto_deploy_command", statement: `ALTER TABLE managed_sites ADD COLUMN auto_deploy_command TEXT NOT NULL AFTER auto_deploy_secret`},
		{name: "auto_deploy_node_version", statement: `ALTER TABLE managed_sites ADD COLUMN auto_deploy_node_version VARCHAR(64) NOT NULL DEFAULT '' AFTER auto_deploy_command`},
		{name: "auto_deploy_notify_email", statement: `ALTER TABLE managed_sites ADD COLUMN auto_deploy_notify_email VARCHAR(255) NOT NULL DEFAULT '' AFTER auto_deploy_node_version`},
	}
	for _, column := range columns {
		var count int
		err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = DATABASE()
			  AND table_name = 'managed_sites'
			  AND column_name = ?
		`, column.name).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.statement); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *Store) ensureManagedSitesNodeVersionColumn(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'managed_sites'
		  AND column_name = 'node_version'
	`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE managed_sites ADD COLUMN node_version VARCHAR(64) NOT NULL DEFAULT '' AFTER php_version`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) ensureManagedSitesLaravelPathsColumn(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'managed_sites'
		  AND column_name = 'laravel_extra_writable_paths'
	`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE managed_sites ADD COLUMN laravel_extra_writable_paths VARCHAR(2048) NOT NULL DEFAULT '' AFTER root_directory`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) ensureManagedSitesRoute53Columns(ctx context.Context) error {
	if s == nil {
		return nil
	}
	columns := []struct {
		name      string
		statement string
	}{
		{name: "aws_route53_zone_id", statement: `ALTER TABLE managed_sites ADD COLUMN aws_route53_zone_id VARCHAR(64) NOT NULL DEFAULT '' AFTER nginx_config_path`},
		{name: "aws_route53_zone_name", statement: `ALTER TABLE managed_sites ADD COLUMN aws_route53_zone_name VARCHAR(255) NOT NULL DEFAULT '' AFTER aws_route53_zone_id`},
	}
	for _, column := range columns {
		var count int
		err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = DATABASE()
			  AND table_name = 'managed_sites'
			  AND column_name = ?
		`, column.name).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.statement); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *Store) ensureManagedSitesBackupColumns(ctx context.Context) error {
	if s == nil {
		return nil
	}
	columns := []struct {
		name      string
		statement string
	}{
		{name: "backup_s3_bucket", statement: `ALTER TABLE managed_sites ADD COLUMN backup_s3_bucket VARCHAR(191) NOT NULL DEFAULT '' AFTER aws_route53_zone_name`},
		{name: "backup_s3_prefix", statement: `ALTER TABLE managed_sites ADD COLUMN backup_s3_prefix VARCHAR(255) NOT NULL DEFAULT '' AFTER backup_s3_bucket`},
		{name: "backup_schedule_hours", statement: `ALTER TABLE managed_sites ADD COLUMN backup_schedule_hours INT NOT NULL DEFAULT 0 AFTER backup_s3_prefix`},
		{name: "backup_retention_count", statement: `ALTER TABLE managed_sites ADD COLUMN backup_retention_count INT NOT NULL DEFAULT 7 AFTER backup_schedule_hours`},
		{name: "backup_last_run_at", statement: `ALTER TABLE managed_sites ADD COLUMN backup_last_run_at DATETIME NULL AFTER backup_retention_count`},
		{name: "backup_last_status", statement: `ALTER TABLE managed_sites ADD COLUMN backup_last_status VARCHAR(64) NOT NULL DEFAULT '' AFTER backup_last_run_at`},
		{name: "backup_last_message", statement: `ALTER TABLE managed_sites ADD COLUMN backup_last_message TEXT NULL AFTER backup_last_status`},
	}
	for _, column := range columns {
		var count int
		err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = DATABASE()
			  AND table_name = 'managed_sites'
			  AND column_name = ?
		`, column.name).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.statement); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *Store) ensureSiteBackupsTable(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS site_backups (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			site_id BIGINT NOT NULL,
			site_name VARCHAR(191) NOT NULL,
			s3_bucket VARCHAR(191) NOT NULL,
			s3_prefix VARCHAR(255) NOT NULL,
			files_key VARCHAR(512) NOT NULL DEFAULT '',
			files_size_bytes BIGINT NOT NULL DEFAULT 0,
			database_key VARCHAR(512) NOT NULL DEFAULT '',
			database_size_bytes BIGINT NOT NULL DEFAULT 0,
			status VARCHAR(64) NOT NULL,
			message TEXT NULL,
			triggered_by VARCHAR(64) NOT NULL DEFAULT 'manual',
			started_at DATETIME NOT NULL,
			finished_at DATETIME NULL,
			INDEX idx_site_backups_site_id (site_id, started_at DESC),
			CONSTRAINT fk_site_backups_site FOREIGN KEY (site_id) REFERENCES managed_sites(id) ON DELETE CASCADE
		)`)
	return err
}

func (s *Store) ensureSiteSubdomainsTable(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS site_subdomains (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			site_id BIGINT NOT NULL,
			subdomain VARCHAR(191) NOT NULL,
			full_domain VARCHAR(255) NOT NULL,
			laravel_extra_writable_paths VARCHAR(2048) NOT NULL DEFAULT '',
			runtime VARCHAR(32) NOT NULL,
			upstream_url VARCHAR(255) NOT NULL DEFAULT '',
			php_version VARCHAR(32) NOT NULL DEFAULT '',
			node_version VARCHAR(64) NOT NULL DEFAULT '',
			repository_url VARCHAR(255) NOT NULL DEFAULT '',
			branch_name VARCHAR(191) NOT NULL DEFAULT '',
			git_credential_protocol VARCHAR(32) NOT NULL DEFAULT '',
			git_credential_username VARCHAR(191) NOT NULL DEFAULT '',
			post_deploy_command TEXT NOT NULL,
			auto_deploy_enabled TINYINT(1) NOT NULL DEFAULT 0,
			auto_deploy_branch VARCHAR(191) NOT NULL DEFAULT '',
			auto_deploy_secret VARCHAR(255) NOT NULL DEFAULT '',
			auto_deploy_command TEXT NOT NULL,
			auto_deploy_node_version VARCHAR(64) NOT NULL DEFAULT '',
			auto_deploy_notify_email VARCHAR(255) NOT NULL DEFAULT '',
			root_directory VARCHAR(255) NOT NULL DEFAULT '',
			nginx_config_path VARCHAR(255) NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			UNIQUE KEY uniq_site_subdomains_full_domain (full_domain),
			INDEX idx_site_subdomains_site_id (site_id),
			CONSTRAINT fk_site_subdomains_site FOREIGN KEY (site_id) REFERENCES managed_sites(id) ON DELETE CASCADE
		)`)
	return err
}

func (s *Store) ensureSiteSubdomainsLaravelPathsColumn(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'site_subdomains'
		  AND column_name = 'laravel_extra_writable_paths'
	`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE site_subdomains ADD COLUMN laravel_extra_writable_paths VARCHAR(2048) NOT NULL DEFAULT '' AFTER full_domain`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) ensureSiteSubdomainsNodeVersionColumn(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'site_subdomains'
		  AND column_name = 'node_version'
	`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE site_subdomains ADD COLUMN node_version VARCHAR(64) NOT NULL DEFAULT '' AFTER php_version`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) ensureSiteSubdomainsDeployColumns(ctx context.Context) error {
	if s == nil {
		return nil
	}
	columns := []struct {
		name      string
		statement string
	}{
		{name: "repository_url", statement: `ALTER TABLE site_subdomains ADD COLUMN repository_url VARCHAR(255) NOT NULL DEFAULT '' AFTER php_version`},
		{name: "branch_name", statement: `ALTER TABLE site_subdomains ADD COLUMN branch_name VARCHAR(191) NOT NULL DEFAULT '' AFTER repository_url`},
		{name: "git_credential_protocol", statement: `ALTER TABLE site_subdomains ADD COLUMN git_credential_protocol VARCHAR(32) NOT NULL DEFAULT '' AFTER branch_name`},
		{name: "git_credential_username", statement: `ALTER TABLE site_subdomains ADD COLUMN git_credential_username VARCHAR(191) NOT NULL DEFAULT '' AFTER git_credential_protocol`},
		{name: "post_deploy_command", statement: `ALTER TABLE site_subdomains ADD COLUMN post_deploy_command TEXT NOT NULL AFTER git_credential_username`},
		{name: "auto_deploy_enabled", statement: `ALTER TABLE site_subdomains ADD COLUMN auto_deploy_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER post_deploy_command`},
		{name: "auto_deploy_branch", statement: `ALTER TABLE site_subdomains ADD COLUMN auto_deploy_branch VARCHAR(191) NOT NULL DEFAULT '' AFTER auto_deploy_enabled`},
		{name: "auto_deploy_secret", statement: `ALTER TABLE site_subdomains ADD COLUMN auto_deploy_secret VARCHAR(255) NOT NULL DEFAULT '' AFTER auto_deploy_branch`},
		{name: "auto_deploy_command", statement: `ALTER TABLE site_subdomains ADD COLUMN auto_deploy_command TEXT NOT NULL AFTER auto_deploy_secret`},
		{name: "auto_deploy_node_version", statement: `ALTER TABLE site_subdomains ADD COLUMN auto_deploy_node_version VARCHAR(64) NOT NULL DEFAULT '' AFTER auto_deploy_command`},
		{name: "auto_deploy_notify_email", statement: `ALTER TABLE site_subdomains ADD COLUMN auto_deploy_notify_email VARCHAR(255) NOT NULL DEFAULT '' AFTER auto_deploy_node_version`},
	}
	for _, column := range columns {
		var count int
		err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = DATABASE()
			  AND table_name = 'site_subdomains'
			  AND column_name = ?
		`, column.name).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.statement); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") || errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *Store) ensureNginxConfigRevisionsTable(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS nginx_config_revisions (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			site_id BIGINT NOT NULL,
			subdomain_id BIGINT NOT NULL DEFAULT 0,
			config_path VARCHAR(255) NOT NULL,
			content MEDIUMTEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_nginx_config_revisions_site_target (site_id, subdomain_id, id DESC),
			CONSTRAINT fk_nginx_config_revisions_site FOREIGN KEY (site_id) REFERENCES managed_sites(id) ON DELETE CASCADE
		)`)
	return err
}

func splitStatements(input string) []string {
	chunks := strings.Split(input, ";")
	statements := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		trimmed := strings.TrimSpace(chunk)
		if trimmed == "" {
			continue
		}
		statements = append(statements, trimmed)
	}
	return statements
}
