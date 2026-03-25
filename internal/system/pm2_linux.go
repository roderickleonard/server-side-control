//go:build linux

package system

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type linuxPM2Manager struct{}

func NewPM2Manager() PM2Manager {
	return linuxPM2Manager{}
}

func (linuxPM2Manager) List(user string) (string, error) {
	return runPM2(user, "list", "--no-color")
}

func (linuxPM2Manager) Restart(user string, processName string) (string, error) {
	return runPM2WithProcess(user, "restart", processName)
}

func (linuxPM2Manager) Reload(user string, processName string) (string, error) {
	return runPM2WithProcess(user, "reload", processName)
}

func (linuxPM2Manager) Start(user string, processName string) (string, error) {
	return runPM2WithProcess(user, "start", processName)
}

func (linuxPM2Manager) Stop(user string, processName string) (string, error) {
	return runPM2WithProcess(user, "stop", processName)
}

func (linuxPM2Manager) Logs(user string, processName string, lines int) (string, error) {
	processName = strings.TrimSpace(processName)
	if processName == "" {
		return "", fmt.Errorf("process name is required")
	}
	if lines <= 0 {
		lines = 100
	}
	return runPM2(user, "logs", processName, "--nostream", "--lines", strconv.Itoa(lines))
}

func runPM2WithProcess(user string, action string, processName string) (string, error) {
	processName = strings.TrimSpace(processName)
	if processName == "" {
		return "", fmt.Errorf("process name is required")
	}
	return runPM2(user, action, processName)
}

func runPM2(user string, args ...string) (string, error) {
	user = strings.TrimSpace(user)
	if !usernamePattern.MatchString(user) {
		return "", ErrInvalidRunAsUser
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var output bytes.Buffer
	commandArgs := append([]string{"-u", user, "--", "pm2"}, args...)
	cmd := exec.CommandContext(ctx, "sudo", commandArgs...)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return output.String(), fmt.Errorf("pm2 %s failed: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(output.String()), nil
}
