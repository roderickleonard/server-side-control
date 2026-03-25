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

	return nil
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
