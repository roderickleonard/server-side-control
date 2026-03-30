//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var ErrInvalidUsername = errors.New("invalid linux username")
var ErrUserExists = errors.New("linux user already exists")
var ErrUserNotFound = errors.New("linux user not found")
var ErrProtectedUser = errors.New("linux user is protected")

var protectedLinuxUsers = map[string]struct{}{
	"root":                {},
	"server-side-control": {},
}

type linuxUserManager struct{}

func NewUserManager() UserManager {
	return linuxUserManager{}
}

func (linuxUserManager) CreateLinuxUser(username string, createHome bool, password string, grantSudo bool) error {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	password = strings.TrimSpace(password)
	if grantSudo && password == "" {
		return fmt.Errorf("sudo-enabled users must have a password")
	}
	if password != "" && !isValidLinuxPassword(password) {
		return ErrInvalidLinuxPassword
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "id", "-u", username).Run(); err == nil {
		return ErrUserExists
	}

	homeDirectory := "/home/" + username
	args := []string{}
	if createHome {
		args = append(args, "--create-home")
	} else {
		args = append(args, "--no-create-home")
	}
	args = append(args,
		"--home-dir", homeDirectory,
		"--shell", "/bin/bash",
		"--user-group",
		username,
	)

	cmd := exec.CommandContext(ctx, "useradd", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("useradd: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if password != "" {
		if err := linuxUserManager{}.SetLinuxUserPassword(username, password); err != nil {
			return err
		}
	}
	if grantSudo {
		if err := linuxUserManager{}.SetLinuxUserSudo(username, true); err != nil {
			return err
		}
	}
	return nil
}

func (linuxUserManager) ListLinuxUsers() ([]LinuxUser, error) {
	content, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	users := make([]LinuxUser, 0)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		username := parts[0]
		homeDirectory := parts[5]
		shell := parts[6]

		if !shouldExposeLinuxUser(username, uid, homeDirectory, shell) {
			continue
		}

		users = append(users, LinuxUser{
			Username:      username,
			UID:           uid,
			HomeDirectory: homeDirectory,
			Shell:         shell,
			PasswordSet:   linuxUserHasPassword(username),
			SudoEnabled:   linuxUserHasSudo(username),
			PasswordlessSudo: linuxUserHasPasswordlessSudo(username),
		})
	}

	sort.Slice(users, func(i int, j int) bool {
		return users[i].Username < users[j].Username
	})

	return users, nil
}

func (linuxUserManager) DeleteLinuxUser(username string, removeHome bool) error {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	if _, ok := protectedLinuxUsers[username]; ok {
		return ErrProtectedUser
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "id", "-u", username).Run(); err != nil {
		return ErrUserNotFound
	}

	args := []string{}
	if removeHome {
		args = append(args, "-r")
	}
	args = append(args, username)

	cmd := exec.CommandContext(ctx, "userdel", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("userdel: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func (linuxUserManager) SetLinuxUserPassword(username string, password string) error {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	if !isValidLinuxPassword(password) {
		return ErrInvalidLinuxPassword
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "id", "-u", username).Run(); err != nil {
		return ErrUserNotFound
	}
	cmd := exec.CommandContext(ctx, "chpasswd")
	cmd.Stdin = strings.NewReader(username + ":" + password)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chpasswd: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (linuxUserManager) SetLinuxUserSudo(username string, enabled bool) error {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	if _, ok := protectedLinuxUsers[username]; ok {
		return ErrProtectedUser
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "id", "-u", username).Run(); err != nil {
		return ErrUserNotFound
	}
	var cmd *exec.Cmd
	if enabled {
		cmd = exec.CommandContext(ctx, "usermod", "-aG", "sudo", username)
	} else {
		cmd = exec.CommandContext(ctx, "gpasswd", "-d", username, "sudo")
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if !enabled && strings.Contains(strings.ToLower(trimmed), "is not a member") {
			return nil
		}
		return fmt.Errorf("sudo membership change failed: %w: %s", err, trimmed)
	}
	if !enabled {
		_ = removeLinuxUserPasswordlessSudo(username)
	}
	return nil
}

func (linuxUserManager) SetLinuxUserPasswordlessSudo(username string, enabled bool) error {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	if _, ok := protectedLinuxUsers[username]; ok {
		return ErrProtectedUser
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "id", "-u", username).Run(); err != nil {
		return ErrUserNotFound
	}
	if enabled {
		if err := linuxUserManager{}.SetLinuxUserSudo(username, true); err != nil {
			return err
		}
		return writeLinuxUserPasswordlessSudo(username)
	}
	return removeLinuxUserPasswordlessSudo(username)
	return nil
}

func linuxUserHasPasswordlessSudo(username string) bool {
	content, err := os.ReadFile(linuxUserPasswordlessSudoPath(username))
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "NOPASSWD:ALL")
}

func linuxUserPasswordlessSudoPath(username string) string {
	return filepath.Join("/etc/sudoers.d", "server-side-control-"+username)
}

func writeLinuxUserPasswordlessSudo(username string) error {
	path := linuxUserPasswordlessSudoPath(username)
	content := []byte(username + " ALL=(ALL:ALL) NOPASSWD:ALL\n")
	if err := os.WriteFile(path, content, 0o440); err != nil {
		return fmt.Errorf("write sudoers drop-in: %w", err)
	}
	if _, err := exec.LookPath("visudo"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output, validateErr := exec.CommandContext(ctx, "visudo", "-cf", path).CombinedOutput()
		if validateErr != nil {
			_ = os.Remove(path)
			return fmt.Errorf("validate sudoers drop-in: %w: %s", validateErr, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func removeLinuxUserPasswordlessSudo(username string) error {
	path := linuxUserPasswordlessSudoPath(username)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove sudoers drop-in: %w", err)
	}
	return nil
}

func isValidLinuxPassword(password string) bool {
	if password == "" {
		return false
	}
	if strings.ContainsAny(password, "\r\n:") {
		return false
	}
	return true
}

func linuxUserHasPassword(username string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "passwd", "-S", username).CombinedOutput()
	if err != nil {
		return false
	}
	fields := strings.Fields(string(output))
	if len(fields) < 2 {
		return false
	}
	status := strings.ToUpper(fields[1])
	return status == "P" || status == "PS"
}

func linuxUserHasSudo(username string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "id", "-nG", username).CombinedOutput()
	if err != nil {
		return false
	}
	for _, group := range strings.Fields(string(output)) {
		if strings.TrimSpace(group) == "sudo" {
			return true
		}
	}
	return false
}

func StreamLinuxUserCreate(username string, createHome bool, password string, grantSudo bool, stdout io.Writer) error {
	_, _ = fmt.Fprintf(stdout, "Creating Linux user %s\n", username)
	if createHome {
		_, _ = fmt.Fprintln(stdout, "Home directory will be created.")
	}
	if grantSudo {
		_, _ = fmt.Fprintln(stdout, "Sudo group membership will be granted.")
	}
	if password != "" {
		_, _ = fmt.Fprintln(stdout, "Password will be set.")
	}
	return linuxUserManager{}.CreateLinuxUser(username, createHome, password, grantSudo)
}

func StreamLinuxUserDelete(username string, removeHome bool, stdout io.Writer) error {
	_, _ = fmt.Fprintf(stdout, "Deleting Linux user %s\n", username)
	if removeHome {
		_, _ = fmt.Fprintln(stdout, "Home directory will also be removed.")
	}
	return linuxUserManager{}.DeleteLinuxUser(username, removeHome)
}

func StreamLinuxUserPassword(username string, password string, stdout io.Writer) error {
	_, _ = fmt.Fprintf(stdout, "Setting password for %s\n", username)
	_ = password
	return linuxUserManager{}.SetLinuxUserPassword(username, password)
}

func StreamLinuxUserSudo(username string, enabled bool, stdout io.Writer) error {
	if enabled {
		_, _ = fmt.Fprintf(stdout, "Granting sudo to %s\n", username)
	} else {
		_, _ = fmt.Fprintf(stdout, "Revoking sudo from %s\n", username)
	}
	return linuxUserManager{}.SetLinuxUserSudo(username, enabled)
}

func StreamLinuxUserPasswordlessSudo(username string, enabled bool, stdout io.Writer) error {
	if enabled {
		_, _ = fmt.Fprintf(stdout, "Enabling passwordless sudo for %s\n", username)
	} else {
		_, _ = fmt.Fprintf(stdout, "Disabling passwordless sudo for %s\n", username)
	}
	return linuxUserManager{}.SetLinuxUserPasswordlessSudo(username, enabled)
}

func shouldExposeLinuxUser(username string, uid int, homeDirectory string, shell string) bool {
	if _, ok := protectedLinuxUsers[username]; ok {
		return false
	}
	if username == "nobody" {
		return false
	}
	if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") {
		return false
	}
	if strings.HasPrefix(homeDirectory, "/home/") || strings.HasPrefix(homeDirectory, "/var/www/") || strings.HasPrefix(homeDirectory, "/srv/") {
		return true
	}
	return uid >= 1000
}
