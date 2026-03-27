package store

import (
	"context"
	"encoding/json"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type PanelUserSecurity struct {
	LinuxUser     string
	TOTPEnabled   bool
	TOTPSecret    string
	TOTPEnabledAt sql.NullTime
	RecoveryCodes []string
	RecoveryGeneratedAt sql.NullTime
}

type PanelUserPasskey struct {
	ID           int64
	LinuxUser    string
	CredentialID string
	Label        string
	PublicKeySPKI string
	SignCount    uint32
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (s *Store) GetPanelUserSecurity(ctx context.Context, username string) (PanelUserSecurity, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return PanelUserSecurity{}, fmt.Errorf("username is required")
	}
	var security PanelUserSecurity
	var recoveryCodesJSON string
	err := s.db.QueryRowContext(ctx, `SELECT linux_user, totp_enabled, totp_secret, totp_enabled_at, recovery_codes_json, recovery_generated_at FROM panel_users WHERE linux_user = ? LIMIT 1`, username).Scan(
		&security.LinuxUser,
		&security.TOTPEnabled,
		&security.TOTPSecret,
		&security.TOTPEnabledAt,
		&recoveryCodesJSON,
		&security.RecoveryGeneratedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return PanelUserSecurity{LinuxUser: username}, nil
		}
		return PanelUserSecurity{}, fmt.Errorf("query panel user security: %w", err)
	}
	if strings.TrimSpace(recoveryCodesJSON) != "" {
		_ = json.Unmarshal([]byte(recoveryCodesJSON), &security.RecoveryCodes)
	}
	return security, nil
}

func (s *Store) SavePanelUserTOTP(ctx context.Context, username string, secret string, enabled bool) error {
	username = strings.TrimSpace(username)
	secret = strings.TrimSpace(secret)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	var enabledAt any
	if enabled {
		enabledAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO panel_users (linux_user, role, enabled, totp_enabled, totp_secret, totp_enabled_at)
		VALUES (?, 'operator', 1, ?, ?, ?)
		ON DUPLICATE KEY UPDATE totp_enabled = VALUES(totp_enabled), totp_secret = VALUES(totp_secret), totp_enabled_at = VALUES(totp_enabled_at)
	`, username, enabled, secret, enabledAt)
	if err != nil {
		return fmt.Errorf("save panel user totp: %w", err)
	}
	return nil
}

func (s *Store) DisablePanelUserTOTP(ctx context.Context, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO panel_users (linux_user, role, enabled, totp_enabled, totp_secret, totp_enabled_at, recovery_codes_json, recovery_generated_at)
		VALUES (?, 'operator', 1, 0, '', NULL, '[]', NULL)
		ON DUPLICATE KEY UPDATE totp_enabled = 0, totp_secret = '', totp_enabled_at = NULL, recovery_codes_json = '[]', recovery_generated_at = NULL
	`, username)
	if err != nil {
		return fmt.Errorf("disable panel user totp: %w", err)
	}
	return nil
}

func (s *Store) SavePanelUserRecoveryCodes(ctx context.Context, username string, hashes []string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	payload, err := json.Marshal(hashes)
	if err != nil {
		return fmt.Errorf("marshal recovery codes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO panel_users (linux_user, role, enabled, recovery_codes_json, recovery_generated_at)
		VALUES (?, 'operator', 1, ?, UTC_TIMESTAMP())
		ON DUPLICATE KEY UPDATE recovery_codes_json = VALUES(recovery_codes_json), recovery_generated_at = UTC_TIMESTAMP()
	`, username, string(payload))
	if err != nil {
		return fmt.Errorf("save panel user recovery codes: %w", err)
	}
	return nil
}

func (s *Store) ListPanelUserPasskeys(ctx context.Context, username string) ([]PanelUserPasskey, error) {
	username = strings.TrimSpace(username)
	rows, err := s.db.QueryContext(ctx, `SELECT id, linux_user, credential_id, label, public_key_spki, sign_count, created_at, updated_at FROM panel_user_passkeys WHERE linux_user = ? ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, fmt.Errorf("list panel user passkeys: %w", err)
	}
	defer rows.Close()
	passkeys := make([]PanelUserPasskey, 0)
	for rows.Next() {
		var passkey PanelUserPasskey
		if err := rows.Scan(&passkey.ID, &passkey.LinuxUser, &passkey.CredentialID, &passkey.Label, &passkey.PublicKeySPKI, &passkey.SignCount, &passkey.CreatedAt, &passkey.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan panel user passkey: %w", err)
		}
		passkeys = append(passkeys, passkey)
	}
	return passkeys, rows.Err()
}

func (s *Store) GetPanelUserPasskeyByCredentialID(ctx context.Context, credentialID string) (PanelUserPasskey, error) {
	credentialID = strings.TrimSpace(credentialID)
	var passkey PanelUserPasskey
	err := s.db.QueryRowContext(ctx, `SELECT id, linux_user, credential_id, label, public_key_spki, sign_count, created_at, updated_at FROM panel_user_passkeys WHERE credential_id = ? LIMIT 1`, credentialID).Scan(
		&passkey.ID,
		&passkey.LinuxUser,
		&passkey.CredentialID,
		&passkey.Label,
		&passkey.PublicKeySPKI,
		&passkey.SignCount,
		&passkey.CreatedAt,
		&passkey.UpdatedAt,
	)
	if err != nil {
		return PanelUserPasskey{}, err
	}
	return passkey, nil
}

func (s *Store) SavePanelUserPasskey(ctx context.Context, username string, credentialID string, label string, publicKeySPKI string, signCount uint32) error {
	username = strings.TrimSpace(username)
	credentialID = strings.TrimSpace(credentialID)
	label = strings.TrimSpace(label)
	publicKeySPKI = strings.TrimSpace(publicKeySPKI)
	if username == "" || credentialID == "" || publicKeySPKI == "" {
		return fmt.Errorf("username, credential id and public key are required")
	}
	if label == "" {
		label = "Passkey"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO panel_user_passkeys (linux_user, credential_id, label, public_key_spki, sign_count)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE label = VALUES(label), public_key_spki = VALUES(public_key_spki), sign_count = VALUES(sign_count)
	`, username, credentialID, label, publicKeySPKI, signCount)
	if err != nil {
		return fmt.Errorf("save panel user passkey: %w", err)
	}
	return nil
}

func (s *Store) UpdatePanelUserPasskeySignCount(ctx context.Context, id int64, signCount uint32) error {
	_, err := s.db.ExecContext(ctx, `UPDATE panel_user_passkeys SET sign_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, signCount, id)
	if err != nil {
		return fmt.Errorf("update panel user passkey sign count: %w", err)
	}
	return nil
}

func (s *Store) DeletePanelUserPasskey(ctx context.Context, username string, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM panel_user_passkeys WHERE id = ? AND linux_user = ?`, id, strings.TrimSpace(username))
	if err != nil {
		return fmt.Errorf("delete panel user passkey: %w", err)
	}
	return nil
}

func (s *Store) TouchPanelUserLastLogin(ctx context.Context, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO panel_users (linux_user, role, enabled, last_login_at)
		VALUES (?, 'operator', 1, UTC_TIMESTAMP())
		ON DUPLICATE KEY UPDATE last_login_at = UTC_TIMESTAMP()
	`, username)
	if err != nil {
		return fmt.Errorf("touch panel user last login: %w", err)
	}
	return nil
}