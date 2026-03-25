//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func (linuxUserManager) CreateLinuxUser(username string, createHome bool) error {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "id", "-u", username).Run(); err == nil {
		return ErrUserExists
	}

	args := []string{}
	if createHome {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}
	args = append(args, username)

	cmd := exec.CommandContext(ctx, "useradd", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("useradd: %w: %s", err, strings.TrimSpace(string(output)))
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

func shouldExposeLinuxUser(username string, uid int, homeDirectory string, shell string) bool {
	if _, ok := protectedLinuxUsers[username]; ok {
		return false
	}
	if username == "nobody" {
		return false
	}
	if uid < 1000 {
		return false
	}
	if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") {
		return false
	}
	return strings.HasPrefix(homeDirectory, "/home/") || strings.HasPrefix(homeDirectory, "/var/www/") || strings.HasPrefix(homeDirectory, "/srv/")
}
