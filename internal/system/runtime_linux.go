//go:build linux

package system

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var nodeVersionPattern = regexp.MustCompile(`^(?:lts(?:/[A-Za-z0-9*._-]+)?|node|v?[0-9]+(?:\.[0-9]+){0,2})$`)
var pm2ProcessPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var npmScriptNamePattern = regexp.MustCompile(`^[A-Za-z0-9:._/-]{1,64}$`)
var scriptPathPattern = regexp.MustCompile(`^[A-Za-z0-9._/@+-][A-Za-z0-9._/@+\-/:]*$`)
var processArgsPattern = regexp.MustCompile(`^[A-Za-z0-9._/@=,+:\-\s]*$`)
var installedNodePattern = regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`)

type linuxRuntimeManager struct{}

func NewRuntimeManager() RuntimeManager {
	return linuxRuntimeManager{}
}

func (linuxRuntimeManager) Inspect(spec RuntimeInspectSpec) (RuntimeStatus, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return RuntimeStatus{}, err
	}
	status := RuntimeStatus{User: strings.TrimSpace(spec.User), HomeDirectory: homeDirectory}
	nvmScriptPath := filepath.Join(homeDirectory, ".nvm", "nvm.sh")
	if _, err := os.Stat(nvmScriptPath); err == nil {
		status.NVMInstalled = true
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		versionsOutput, _ := runBashAsUser(ctx, status.User, buildNVMCommand(homeDirectory, "nvm ls --no-colors"))
		status.InstalledNodeVersions = uniqueSortedMatches(installedNodePattern.FindAllString(versionsOutput, -1))
		defaultOutput, _ := runBashAsUser(ctx, status.User, buildNVMCommand(homeDirectory, "nvm alias default"))
		status.DefaultNodeVersion = parseDefaultNodeVersion(defaultOutput)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pm2Output, _ := runBashAsUser(ctx, status.User, buildShellWithOptionalNVM(homeDirectory, "command -v pm2 >/dev/null 2>&1 && echo installed || true"))
	status.PM2Installed = strings.Contains(pm2Output, "installed")
	return status, nil
}

func (linuxRuntimeManager) InstallNVM(user string) (string, error) {
	homeDirectory, err := lookupUserHome(user)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	script := fmt.Sprintf("set -e; export HOME=%s; export PROFILE=%s; if [ -s %s ]; then echo 'NVM already installed'; exit 0; fi; if command -v curl >/dev/null 2>&1; then curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash; elif command -v wget >/dev/null 2>&1; then wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash; else echo 'curl or wget is required'; exit 1; fi",
		shellQuote(homeDirectory),
		shellQuote(filepath.Join(homeDirectory, ".bashrc")),
		shellQuote(filepath.Join(homeDirectory, ".nvm", "nvm.sh")),
	)
	return runBashAsUser(ctx, user, script)
}

func (linuxRuntimeManager) InstallNode(spec NodeInstallSpec) (string, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(spec.Version)
	if !nodeVersionPattern.MatchString(version) {
		return "", ErrInvalidNodeVersion
	}
	if _, err := os.Stat(filepath.Join(homeDirectory, ".nvm", "nvm.sh")); err != nil {
		return "", ErrNVMNotInstalled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := "nvm install " + shellQuote(version)
	if spec.SetDefault {
		command += " && nvm alias default " + shellQuote(version)
	}
	command += " && nvm use " + shellQuote(version)
	return runBashAsUser(ctx, spec.User, buildNVMCommand(homeDirectory, command))
}

func (linuxRuntimeManager) InstallPM2(spec PM2InstallSpec) (string, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(homeDirectory, ".nvm", "nvm.sh")); err != nil {
		return "", ErrNVMNotInstalled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := ""
	if strings.TrimSpace(spec.NodeVersion) != "" {
		if !nodeVersionPattern.MatchString(strings.TrimSpace(spec.NodeVersion)) {
			return "", ErrInvalidNodeVersion
		}
		command = "nvm install " + shellQuote(strings.TrimSpace(spec.NodeVersion)) + " && nvm use " + shellQuote(strings.TrimSpace(spec.NodeVersion)) + " && "
		command += "npm install -g pm2"
	} else {
		command = "npm install -g pm2"
	}
	return runBashAsUser(ctx, spec.User, buildNVMCommand(homeDirectory, command))
}

func (linuxRuntimeManager) StartPM2(spec PM2StartSpec) (string, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(homeDirectory, ".nvm", "nvm.sh")); err != nil {
		return "", ErrNVMNotInstalled
	}
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.ProcessName = strings.TrimSpace(spec.ProcessName)
	spec.ScriptPath = strings.TrimSpace(spec.ScriptPath)
	spec.Arguments = strings.TrimSpace(spec.Arguments)
	spec.NodeVersion = strings.TrimSpace(spec.NodeVersion)
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return "", ErrInvalidTargetDirectory
	}
	if !pm2ProcessPattern.MatchString(spec.ProcessName) {
		return "", ErrInvalidProcessName
	}
	if !scriptPathPattern.MatchString(spec.ScriptPath) {
		return "", ErrInvalidScriptPath
	}
	if spec.Arguments != "" && !processArgsPattern.MatchString(spec.Arguments) {
		return "", ErrInvalidArguments
	}
	if spec.NodeVersion != "" && !nodeVersionPattern.MatchString(spec.NodeVersion) {
		return "", ErrInvalidNodeVersion
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pm2Command := ""
	if spec.NodeVersion != "" {
		pm2Command += "nvm install " + shellQuote(spec.NodeVersion) + " && nvm use " + shellQuote(spec.NodeVersion) + " && "
	}
	pm2Command += "cd " + shellQuote(spec.WorkingDirectory)
	pm2Command += " && pm2 delete " + shellQuote(spec.ProcessName) + " >/dev/null 2>&1 || true"
	pm2Command += " && pm2 start " + shellQuote(spec.ScriptPath) + " --name " + shellQuote(spec.ProcessName) + " --cwd " + shellQuote(spec.WorkingDirectory)
	if spec.Arguments != "" {
		pm2Command += " -- " + shellJoin(strings.Fields(spec.Arguments))
	}
	pm2Command += " && pm2 save"
	return runBashAsUser(ctx, spec.User, buildNVMCommand(homeDirectory, pm2Command))
}

func (linuxRuntimeManager) RunNPMScript(spec NPMScriptSpec) (string, error) {
	spec.User = strings.TrimSpace(spec.User)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.ScriptName = strings.TrimSpace(spec.ScriptName)
	spec.NodeVersion = strings.TrimSpace(spec.NodeVersion)
	if !usernamePattern.MatchString(spec.User) {
		return "", ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return "", ErrInvalidTargetDirectory
	}
	if !npmScriptNamePattern.MatchString(spec.ScriptName) {
		return "", fmt.Errorf("invalid npm script name")
	}
	if spec.NodeVersion != "" && !nodeVersionPattern.MatchString(spec.NodeVersion) {
		return "", ErrInvalidNodeVersion
	}
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	nvmUse := ""
	if spec.NodeVersion != "" {
		nvmUse = "nvm use " + shellQuote(spec.NodeVersion) + " && "
	}
	cmd := nvmUse + "cd " + shellQuote(spec.WorkingDirectory) + " && npm run " + shellQuote(spec.ScriptName)
	return runBashAsUser(ctx, spec.User, buildNVMCommand(homeDirectory, cmd))
}

func StreamNPMScript(spec NPMScriptSpec, stdout io.Writer, stderr io.Writer) error {
	spec.User = strings.TrimSpace(spec.User)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.ScriptName = strings.TrimSpace(spec.ScriptName)
	spec.NodeVersion = strings.TrimSpace(spec.NodeVersion)
	if !usernamePattern.MatchString(spec.User) {
		return ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return ErrInvalidTargetDirectory
	}
	if !npmScriptNamePattern.MatchString(spec.ScriptName) {
		return fmt.Errorf("invalid npm script name")
	}
	if spec.NodeVersion != "" && !nodeVersionPattern.MatchString(spec.NodeVersion) {
		return ErrInvalidNodeVersion
	}
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	nvmUse := ""
	if spec.NodeVersion != "" {
		nvmUse = "nvm use " + shellQuote(spec.NodeVersion) + " && "
	}
	cmd := nvmUse + "cd " + shellQuote(spec.WorkingDirectory) + " && npm run " + shellQuote(spec.ScriptName)
	return runBashAsUserStream(ctx, spec.User, buildNVMCommand(homeDirectory, cmd), stdout, stderr)
}

func (linuxRuntimeManager) RunNPMInstall(spec NPMInstallSpec) (string, error) {
	spec.User = strings.TrimSpace(spec.User)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.NodeVersion = strings.TrimSpace(spec.NodeVersion)
	if !usernamePattern.MatchString(spec.User) {
		return "", ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return "", ErrInvalidTargetDirectory
	}
	if spec.NodeVersion != "" && !nodeVersionPattern.MatchString(spec.NodeVersion) {
		return "", ErrInvalidNodeVersion
	}
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	nvmUse := ""
	if spec.NodeVersion != "" {
		nvmUse = "nvm use " + shellQuote(spec.NodeVersion) + " && "
	}
	installCmd := "npm install"
	if spec.CI {
		installCmd = "npm ci"
	}
	cmd := nvmUse + "cd " + shellQuote(spec.WorkingDirectory) + " && " + installCmd
	return runBashAsUser(ctx, spec.User, buildNVMCommand(homeDirectory, cmd))
}

func StreamNPMInstall(spec NPMInstallSpec, stdout io.Writer, stderr io.Writer) error {
	spec.User = strings.TrimSpace(spec.User)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.NodeVersion = strings.TrimSpace(spec.NodeVersion)
	if !usernamePattern.MatchString(spec.User) {
		return ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return ErrInvalidTargetDirectory
	}
	if spec.NodeVersion != "" && !nodeVersionPattern.MatchString(spec.NodeVersion) {
		return ErrInvalidNodeVersion
	}
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	nvmUse := ""
	if spec.NodeVersion != "" {
		nvmUse = "nvm use " + shellQuote(spec.NodeVersion) + " && "
	}
	installCmd := "npm install"
	if spec.CI {
		installCmd = "npm ci"
	}
	cmd := nvmUse + "cd " + shellQuote(spec.WorkingDirectory) + " && " + installCmd
	return runBashAsUserStream(ctx, spec.User, buildNVMCommand(homeDirectory, cmd), stdout, stderr)
}

func lookupUserHome(username string) (string, error) {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return "", ErrInvalidUsername
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "getent", "passwd", username).Output()
	if err != nil {
		return "", ErrUserNotFound
	}
	parts := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(parts) < 6 || strings.TrimSpace(parts[5]) == "" {
		return "", ErrUserNotFound
	}
	return strings.TrimSpace(parts[5]), nil
}

func lookupUserIDs(username string) (int, int, error) {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return 0, 0, ErrInvalidUsername
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uidOutput, err := exec.CommandContext(ctx, "id", "-u", username).Output()
	if err != nil {
		return 0, 0, ErrUserNotFound
	}
	gidOutput, err := exec.CommandContext(ctx, "id", "-g", username).Output()
	if err != nil {
		return 0, 0, ErrUserNotFound
	}
	uid, err := strconv.Atoi(strings.TrimSpace(string(uidOutput)))
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(strings.TrimSpace(string(gidOutput)))
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func runBashAsUser(ctx context.Context, user string, script string) (string, error) {
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, "sudo", "-u", user, "--", "bash", "-lc", script)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return output.String(), fmt.Errorf("command failed: %w", err)
	}
	return strings.TrimSpace(output.String()), nil
}

func runBashAsUserStream(ctx context.Context, user string, script string, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = stdout
	}
	cmd := exec.CommandContext(ctx, "sudo", "-u", user, "--", "bash", "-lc", script)
	cmdStdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmdStderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stdout, cmdStdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stderr, cmdStderr)
	}()
	err = cmd.Wait()
	wg.Wait()
	if err != nil {
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

func buildNVMCommand(homeDirectory string, command string) string {
	return fmt.Sprintf("set -e; export HOME=%s; export NVM_DIR=%s; [ -s \"$NVM_DIR/nvm.sh\" ] || { echo 'NVM is not installed'; exit 1; }; . \"$NVM_DIR/nvm.sh\"; %s",
		shellQuote(homeDirectory),
		shellQuote(filepath.Join(homeDirectory, ".nvm")),
		command,
	)
}

func buildShellWithOptionalNVM(homeDirectory string, command string) string {
	return fmt.Sprintf("export HOME=%s; export NVM_DIR=%s; if [ -s \"$NVM_DIR/nvm.sh\" ]; then . \"$NVM_DIR/nvm.sh\"; fi; %s",
		shellQuote(homeDirectory),
		shellQuote(filepath.Join(homeDirectory, ".nvm")),
		command,
	)
}

func uniqueSortedMatches(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func parseDefaultNodeVersion(output string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "default ->") {
			continue
		}
		matches := installedNodePattern.FindAllString(line, -1)
		if len(matches) > 0 {
			return matches[len(matches)-1]
		}
	}
	return ""
}

func shellJoin(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}