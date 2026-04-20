//go:build linux

package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var validSSHKeyTypes = map[string]struct{}{
	"ssh-rsa":                            {},
	"ssh-ed25519":                        {},
	"ssh-dss":                            {},
	"ecdsa-sha2-nistp256":                {},
	"ecdsa-sha2-nistp384":                {},
	"ecdsa-sha2-nistp521":                {},
	"sk-ssh-ed25519@openssh.com":         {},
	"sk-ecdsa-sha2-nistp256@openssh.com": {},
}

type linuxSSHAccountManager struct{}

func NewSSHAccountManager() SSHAccountManager {
	return linuxSSHAccountManager{}
}

func (linuxSSHAccountManager) Inspect(username string) (SSHAccountStatus, error) {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return SSHAccountStatus{}, ErrInvalidUsername
	}
	home, err := lookupUserHome(username)
	if err != nil {
		return SSHAccountStatus{}, err
	}
	status := SSHAccountStatus{
		Username:           username,
		HomeDirectory:      home,
		AuthorizedKeysPath: filepath.Join(home, ".ssh", "authorized_keys"),
		PasswordSet:        linuxUserHasPassword(username),
		Shell:              lookupUserShell(username),
	}
	status.LoginDisabled = strings.Contains(status.Shell, "nologin") || strings.Contains(status.Shell, "false")
	keys, err := readAuthorizedKeys(status.AuthorizedKeysPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return status, err
	}
	status.Keys = keys
	return status, nil
}

func (linuxSSHAccountManager) AddKey(spec SSHAddKeySpec) error {
	username := strings.TrimSpace(spec.Username)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	key := strings.TrimSpace(spec.PublicKey)
	if !isValidSSHPublicKey(key) {
		return ErrInvalidSSHPublicKey
	}
	fingerprint, err := fingerprintForKey(key)
	if err != nil {
		return ErrInvalidSSHPublicKey
	}
	home, err := lookupUserHome(username)
	if err != nil {
		return err
	}
	uid, gid, err := lookupUserIDs(username)
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	keysPath := filepath.Join(sshDir, "authorized_keys")
	if err := ensureDirectoryOwned(sshDir, 0o700, uid, gid); err != nil {
		return err
	}
	existing, _ := readAuthorizedKeys(keysPath)
	for _, entry := range existing {
		if entry.Fingerprint == fingerprint {
			return nil
		}
	}
	file, err := os.OpenFile(keysPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open authorized_keys: %w", err)
	}
	info, statErr := file.Stat()
	if statErr == nil && info.Size() > 0 {
		if _, err := file.WriteString("\n"); err != nil {
			file.Close()
			return err
		}
	}
	if _, err := file.WriteString(key + "\n"); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(keysPath, 0o600); err != nil {
		return err
	}
	if err := os.Chown(keysPath, uid, gid); err != nil {
		return err
	}
	return nil
}

func (linuxSSHAccountManager) RemoveKey(spec SSHRemoveKeySpec) error {
	username := strings.TrimSpace(spec.Username)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	fingerprint := strings.TrimSpace(spec.Fingerprint)
	if fingerprint == "" {
		return ErrSSHKeyNotFound
	}
	home, err := lookupUserHome(username)
	if err != nil {
		return err
	}
	uid, gid, err := lookupUserIDs(username)
	if err != nil {
		return err
	}
	keysPath := filepath.Join(home, ".ssh", "authorized_keys")
	content, err := os.ReadFile(keysPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrSSHKeyNotFound
		}
		return err
	}
	lines := strings.Split(string(content), "\n")
	retained := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			retained = append(retained, line)
			continue
		}
		lineFp, fpErr := fingerprintForKey(trimmed)
		if fpErr != nil {
			retained = append(retained, line)
			continue
		}
		if lineFp == fingerprint {
			removed = true
			continue
		}
		retained = append(retained, line)
	}
	if !removed {
		return ErrSSHKeyNotFound
	}
	newContent := strings.Join(retained, "\n")
	if err := os.WriteFile(keysPath, []byte(newContent), 0o600); err != nil {
		return err
	}
	if err := os.Chown(keysPath, uid, gid); err != nil {
		return err
	}
	return nil
}

func (linuxSSHAccountManager) SetPassword(spec SSHPasswordSpec) error {
	return linuxUserManager{}.SetLinuxUserPassword(spec.Username, spec.Password)
}

func lookupUserShell(username string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "getent", "passwd", username).Output()
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(parts) < 7 {
		return ""
	}
	return strings.TrimSpace(parts[6])
}

func isValidSSHPublicKey(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	if strings.ContainsAny(key, "\r\n") {
		return false
	}
	parts := strings.SplitN(key, " ", 3)
	if len(parts) < 2 {
		return false
	}
	keyType := strings.TrimSpace(parts[0])
	if _, ok := validSSHKeyTypes[keyType]; !ok {
		return false
	}
	body := strings.TrimSpace(parts[1])
	if len(body) < 10 {
		return false
	}
	for _, c := range body {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

func fingerprintForKey(key string) (string, error) {
	tmp, err := os.CreateTemp("", "ssh-key-*.pub")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strings.TrimSpace(key) + "\n"); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ssh-keygen", "-lE", "sha256", "-f", tmp.Name()).Output()
	if err != nil {
		return "", fmt.Errorf("fingerprint: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 2 {
		return "", errors.New("unexpected ssh-keygen output")
	}
	return fields[1], nil
}

func readAuthorizedKeys(path string) ([]SSHKeyInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	keys := make([]SSHKeyInfo, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	index := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		keyType := strings.TrimSpace(parts[0])
		if _, ok := validSSHKeyTypes[keyType]; !ok {
			continue
		}
		comment := ""
		if len(parts) >= 3 {
			comment = strings.TrimSpace(parts[2])
		}
		fingerprint, err := fingerprintForKey(line)
		if err != nil {
			continue
		}
		preview := parts[1]
		if len(preview) > 24 {
			preview = preview[:12] + "..." + preview[len(preview)-8:]
		}
		index++
		keys = append(keys, SSHKeyInfo{
			Index:       index,
			Type:        keyType,
			Fingerprint: fingerprint,
			Comment:     comment,
			Preview:     preview,
		})
	}
	return keys, scanner.Err()
}

func ensureDirectoryOwned(path string, mode os.FileMode, uid int, gid int) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return nil
}

func StreamSSHAddKey(spec SSHAddKeySpec, stdout io.Writer) error {
	_, _ = fmt.Fprintf(stdout, "Adding SSH public key for %s\n", spec.Username)
	return linuxSSHAccountManager{}.AddKey(spec)
}

func StreamSSHRemoveKey(spec SSHRemoveKeySpec, stdout io.Writer) error {
	_, _ = fmt.Fprintf(stdout, "Removing SSH key %s for %s\n", spec.Fingerprint, spec.Username)
	return linuxSSHAccountManager{}.RemoveKey(spec)
}
