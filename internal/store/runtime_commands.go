package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/kaganyegin/server-side-control/internal/domain"
)

func (s *Store) ListSiteRuntimeCommands(ctx context.Context, siteID int64) ([]domain.SiteRuntimeCommand, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, site_id, name, command_body, node_version, created_at, updated_at FROM site_runtime_commands WHERE site_id = ? ORDER BY name ASC, id ASC`, siteID)
	if err != nil {
		return nil, fmt.Errorf("list site runtime commands: %w", err)
	}
	defer rows.Close()
	commands := make([]domain.SiteRuntimeCommand, 0)
	for rows.Next() {
		var command domain.SiteRuntimeCommand
		if err := rows.Scan(&command.ID, &command.SiteID, &command.Name, &command.CommandBody, &command.NodeVersion, &command.CreatedAt, &command.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan site runtime command: %w", err)
		}
		commands = append(commands, command)
	}
	return commands, rows.Err()
}

func (s *Store) UpsertSiteRuntimeCommand(ctx context.Context, command domain.SiteRuntimeCommand) (int64, error) {
	if s == nil {
		return 0, errors.New("store is not configured")
	}
	if command.ID > 0 {
		_, err := s.db.ExecContext(ctx, `UPDATE site_runtime_commands SET name = ?, command_body = ?, node_version = ? WHERE id = ? AND site_id = ?`, command.Name, command.CommandBody, command.NodeVersion, command.ID, command.SiteID)
		if err != nil {
			return 0, fmt.Errorf("update site runtime command: %w", err)
		}
		return command.ID, nil
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO site_runtime_commands (site_id, name, command_body, node_version) VALUES (?, ?, ?, ?)`, command.SiteID, command.Name, command.CommandBody, command.NodeVersion)
	if err != nil {
		return 0, fmt.Errorf("insert site runtime command: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read site runtime command id: %w", err)
	}
	return id, nil
}

func (s *Store) DeleteSiteRuntimeCommand(ctx context.Context, siteID int64, commandID int64) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM site_runtime_commands WHERE id = ? AND site_id = ?`, commandID, siteID)
	if err != nil {
		return fmt.Errorf("delete site runtime command: %w", err)
	}
	return nil
}

func (s *Store) ListSubdomainRuntimeCommands(ctx context.Context, subdomainID int64) ([]domain.SiteRuntimeCommand, error) {
	if s == nil {
		return nil, errors.New("store is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, subdomain_id, name, command_body, node_version, created_at, updated_at FROM subdomain_runtime_commands WHERE subdomain_id = ? ORDER BY name ASC, id ASC`, subdomainID)
	if err != nil {
		return nil, fmt.Errorf("list subdomain runtime commands: %w", err)
	}
	defer rows.Close()
	commands := make([]domain.SiteRuntimeCommand, 0)
	for rows.Next() {
		var command domain.SiteRuntimeCommand
		if err := rows.Scan(&command.ID, &command.SubdomainID, &command.Name, &command.CommandBody, &command.NodeVersion, &command.CreatedAt, &command.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan subdomain runtime command: %w", err)
		}
		commands = append(commands, command)
	}
	return commands, rows.Err()
}

func (s *Store) UpsertSubdomainRuntimeCommand(ctx context.Context, command domain.SiteRuntimeCommand) (int64, error) {
	if s == nil {
		return 0, errors.New("store is not configured")
	}
	if command.ID > 0 {
		_, err := s.db.ExecContext(ctx, `UPDATE subdomain_runtime_commands SET name = ?, command_body = ?, node_version = ? WHERE id = ? AND subdomain_id = ?`, command.Name, command.CommandBody, command.NodeVersion, command.ID, command.SubdomainID)
		if err != nil {
			return 0, fmt.Errorf("update subdomain runtime command: %w", err)
		}
		return command.ID, nil
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO subdomain_runtime_commands (subdomain_id, name, command_body, node_version) VALUES (?, ?, ?, ?)`, command.SubdomainID, command.Name, command.CommandBody, command.NodeVersion)
	if err != nil {
		return 0, fmt.Errorf("insert subdomain runtime command: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read subdomain runtime command id: %w", err)
	}
	return id, nil
}

func (s *Store) DeleteSubdomainRuntimeCommand(ctx context.Context, subdomainID int64, commandID int64) error {
	if s == nil {
		return errors.New("store is not configured")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM subdomain_runtime_commands WHERE id = ? AND subdomain_id = ?`, commandID, subdomainID)
	if err != nil {
		return fmt.Errorf("delete subdomain runtime command: %w", err)
	}
	return nil
}