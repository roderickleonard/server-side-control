package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

func (s *Store) CreateDeploymentRelease(ctx context.Context, release domain.DeploymentRelease) error {
	if s == nil {
		return errors.New("store is not configured")
	}

	query := `INSERT INTO deployment_releases (
		repository_url,
		branch_name,
		target_directory,
		run_as_user,
		action,
		status,
		commit_sha,
		previous_commit_sha,
		output
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		release.RepositoryURL,
		release.BranchName,
		release.TargetDirectory,
		release.RunAsUser,
		release.Action,
		release.Status,
		release.CommitSHA,
		release.PreviousCommitSHA,
		release.Output,
	)
	if err != nil {
		return fmt.Errorf("insert deployment release: %w", err)
	}
	return nil
}

func (s *Store) ListDeploymentReleases(ctx context.Context, limit int) ([]domain.DeploymentRelease, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `SELECT id, repository_url, branch_name, target_directory, run_as_user, action, status, commit_sha, previous_commit_sha, output, created_at FROM deployment_releases ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list deployment releases: %w", err)
	}
	defer rows.Close()

	releases := make([]domain.DeploymentRelease, 0, limit)
	for rows.Next() {
		var release domain.DeploymentRelease
		if err := rows.Scan(
			&release.ID,
			&release.RepositoryURL,
			&release.BranchName,
			&release.TargetDirectory,
			&release.RunAsUser,
			&release.Action,
			&release.Status,
			&release.CommitSHA,
			&release.PreviousCommitSHA,
			&release.Output,
			&release.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan deployment release: %w", err)
		}
		releases = append(releases, release)
	}
	return releases, rows.Err()
}
