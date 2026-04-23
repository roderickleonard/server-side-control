package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

// UpdateManagedSiteBackupConfig persists the bucket / region / prefix /
// schedule / retention settings for a site. Setting scheduleHours = 0
// means "disabled".
func (s *Store) UpdateManagedSiteBackupConfig(ctx context.Context, name string, bucket string, region string, prefix string, scheduleHours int, retentionCount int) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE managed_sites SET backup_s3_bucket = ?, backup_s3_region = ?, backup_s3_prefix = ?, backup_schedule_hours = ?, backup_retention_count = ? WHERE name = ?`,
		bucket, region, prefix, scheduleHours, retentionCount, name)
	if err != nil {
		return fmt.Errorf("update managed site backup config: %w", err)
	}
	return nil
}

// UpdateManagedSiteBackupStatus records the outcome of the most recent
// backup attempt for the site (success / failure + message).
func (s *Store) UpdateManagedSiteBackupStatus(ctx context.Context, name string, status string, message string, lastRunAtUnix int64) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE managed_sites SET backup_last_run_at = FROM_UNIXTIME(?), backup_last_status = ?, backup_last_message = ? WHERE name = ?`,
		lastRunAtUnix, status, message, name)
	if err != nil {
		return fmt.Errorf("update managed site backup status: %w", err)
	}
	return nil
}

// CreateSiteBackup inserts a row in the site_backups history table and
// returns the new ID so the helper run can update it on completion.
func (s *Store) CreateSiteBackup(ctx context.Context, backup domain.SiteBackup) (int64, error) {
	if s == nil {
		return 0, errors.New("store is not configured")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO site_backups (
		site_id, site_name, s3_bucket, s3_prefix, files_key, files_size_bytes, database_key, database_size_bytes, status, message, triggered_by, started_at, finished_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		backup.SiteID, backup.SiteName, backup.S3Bucket, backup.S3Prefix,
		backup.FilesKey, backup.FilesSizeBytes,
		backup.DatabaseKey, backup.DatabaseSizeBytes,
		backup.Status, backup.Message, backup.TriggeredBy, backup.StartedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("insert site backup: %w", err)
	}
	id, _ := result.LastInsertId()
	return id, nil
}

// FinishSiteBackup updates the inserted backup row with final status,
// keys, sizes, and finished_at.
func (s *Store) FinishSiteBackup(ctx context.Context, backup domain.SiteBackup) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE site_backups SET files_key = ?, files_size_bytes = ?, database_key = ?, database_size_bytes = ?, status = ?, message = ?, finished_at = NOW() WHERE id = ?`,
		backup.FilesKey, backup.FilesSizeBytes,
		backup.DatabaseKey, backup.DatabaseSizeBytes,
		backup.Status, backup.Message, backup.ID)
	if err != nil {
		return fmt.Errorf("finish site backup: %w", err)
	}
	return nil
}

// ListSiteBackups returns the most recent backups for a site (newest
// first). limit ≤ 0 falls back to 25.
func (s *Store) ListSiteBackups(ctx context.Context, siteID int64, limit int) ([]domain.SiteBackup, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	if limit <= 0 {
		limit = 25
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, site_id, site_name, s3_bucket, s3_prefix, files_key, files_size_bytes, database_key, database_size_bytes, status, message, triggered_by, started_at, finished_at FROM site_backups WHERE site_id = ? ORDER BY started_at DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, fmt.Errorf("list site backups: %w", err)
	}
	defer rows.Close()

	backups := make([]domain.SiteBackup, 0)
	for rows.Next() {
		var backup domain.SiteBackup
		var message sql.NullString
		var finishedAt sql.NullTime
		if err := rows.Scan(
			&backup.ID,
			&backup.SiteID,
			&backup.SiteName,
			&backup.S3Bucket,
			&backup.S3Prefix,
			&backup.FilesKey,
			&backup.FilesSizeBytes,
			&backup.DatabaseKey,
			&backup.DatabaseSizeBytes,
			&backup.Status,
			&message,
			&backup.TriggeredBy,
			&backup.StartedAt,
			&finishedAt,
		); err != nil {
			return nil, fmt.Errorf("scan site backup: %w", err)
		}
		if message.Valid {
			backup.Message = message.String
		}
		if finishedAt.Valid {
			t := finishedAt.Time
			backup.FinishedAt = &t
		}
		backups = append(backups, backup)
	}
	return backups, rows.Err()
}

// ListSitesDueForBackup returns sites whose backup_schedule_hours > 0
// and whose backup_last_run_at is older than scheduleHours.
func (s *Store) ListSitesDueForBackup(ctx context.Context) ([]domain.ManagedSite, error) {
	sites, err := s.ListManagedSites(ctx)
	if err != nil {
		return nil, err
	}
	due := make([]domain.ManagedSite, 0)
	for _, site := range sites {
		if site.BackupScheduleHours <= 0 || site.BackupS3Bucket == "" {
			continue
		}
		if site.BackupLastRunAt == nil {
			due = append(due, site)
			continue
		}
		if site.BackupLastRunAt.IsZero() {
			due = append(due, site)
			continue
		}
		thresholdSeconds := int64(site.BackupScheduleHours) * 3600
		elapsed := time.Now().Unix() - site.BackupLastRunAt.Unix()
		if elapsed >= thresholdSeconds {
			due = append(due, site)
		}
	}
	return due, nil
}
