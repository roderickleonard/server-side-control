package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

func (s *Store) SaveDatabaseBackupToken(ctx context.Context, entry domain.DatabaseBackupToken) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO database_backup_tokens (token, database_name, recipient_email, file_path, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)`, entry.Token, entry.DatabaseName, entry.RecipientEmail, entry.FilePath, entry.CreatedBy, entry.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert database backup token: %w", err)
	}
	return nil
}

func (s *Store) GetDatabaseBackupToken(ctx context.Context, token string) (domain.DatabaseBackupToken, error) {
	if s == nil {
		return domain.DatabaseBackupToken{}, errors.New("store is not configured")
	}
	var entry domain.DatabaseBackupToken
	err := s.db.QueryRowContext(ctx, `SELECT token, database_name, recipient_email, file_path, created_by, created_at, expires_at, downloaded_at FROM database_backup_tokens WHERE token = ? LIMIT 1`, token).Scan(&entry.Token, &entry.DatabaseName, &entry.RecipientEmail, &entry.FilePath, &entry.CreatedBy, &entry.CreatedAt, &entry.ExpiresAt, &entry.DownloadedAt)
	if err != nil {
		return domain.DatabaseBackupToken{}, err
	}
	return entry, nil
}

func (s *Store) MarkDatabaseBackupDownloaded(ctx context.Context, token string, downloadedAt time.Time) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE database_backup_tokens SET downloaded_at = ? WHERE token = ?`, downloadedAt, token)
	if err != nil {
		return fmt.Errorf("mark database backup downloaded: %w", err)
	}
	return nil
}

func (s *Store) DeleteDatabaseBackupToken(ctx context.Context, token string) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM database_backup_tokens WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("delete database backup token: %w", err)
	}
	return nil
}

func (s *Store) ListExpiredDatabaseBackupTokens(ctx context.Context, now time.Time) ([]domain.DatabaseBackupToken, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT token, database_name, recipient_email, file_path, created_by, created_at, expires_at, downloaded_at FROM database_backup_tokens WHERE expires_at <= ? OR downloaded_at IS NOT NULL`, now)
	if err != nil {
		return nil, fmt.Errorf("list expired database backup tokens: %w", err)
	}
	defer rows.Close()
	items := make([]domain.DatabaseBackupToken, 0)
	for rows.Next() {
		var entry domain.DatabaseBackupToken
		if err := rows.Scan(&entry.Token, &entry.DatabaseName, &entry.RecipientEmail, &entry.FilePath, &entry.CreatedBy, &entry.CreatedAt, &entry.ExpiresAt, &entry.DownloadedAt); err != nil {
			return nil, fmt.Errorf("scan database backup token: %w", err)
		}
		items = append(items, entry)
	}
	return items, rows.Err()
}