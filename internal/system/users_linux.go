//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var ErrInvalidUsername = errors.New("invalid linux username")
var ErrUserExists = errors.New("linux user already exists")

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
