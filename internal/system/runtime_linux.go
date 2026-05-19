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
	status.AvailableNodeVersions = commonNodeVersionChoices()
	nvmScriptPath := filepath.Join(homeDirectory, ".nvm", "nvm.sh")
	if _, err := os.Stat(nvmScriptPath); err == nil {
		status.NVMInstalled = true
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		versionsOutput, _ := runBashAsUser(ctx, status.User, buildNVMCommand(homeDirectory, "nvm ls --no-colors"))
		status.InstalledNodeVersions = uniqueSortedMatches(installedNodePattern.FindAllString(versionsOutput, -1))
		defaultOutput, _ := runBashAsUser(ctx, status.User, buildNVMCommand(homeDirectory, "nvm alias default"))
		status.DefaultNodeVersion = parseDefaultNodeVersion(defaultOutput)
		status.AvailableNodeVersions = listAvailableNodeVersions(status.User, homeDirectory)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pm2Output, _ := runBashAsUser(ctx, status.User, buildShellWithOptionalNVM(homeDirectory, "command -v pm2 >/dev/null 2>&1 && echo installed || true"))
	status.PM2Installed = strings.Contains(pm2Output, "installed")
	composerCtx, composerCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer composerCancel()
	composerOutput, _ := runBashAsRoot(composerCtx, "command -v composer >/dev/null 2>&1 && composer --version --no-ansi 2>/dev/null || true")
	status.ComposerVersion = strings.TrimSpace(composerOutput)
	status.ComposerInstalled = status.ComposerVersion != ""
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

func (linuxRuntimeManager) InstallComposer() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runBashAsRoot(ctx, composerInstallScript())
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
	resolvedScriptPath, err := resolvePM2ScriptPath(spec.WorkingDirectory, spec.ScriptPath)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Resolve the exact node binary path so that PM2 uses a pinned interpreter
	// for this process.  Using `--interpreter /full/path/to/node` means the
	// process keeps running on the correct Node version even when nvm alias
	// default is later changed by another site or subdomain.
	interpreterFlag := ""
	if spec.NodeVersion != "" {
		installAndFind := buildNVMCommand(homeDirectory,
			"nvm install "+shellQuote(spec.NodeVersion)+" && nvm which "+shellQuote(spec.NodeVersion))
		nodePath, findErr := runBashAsUser(ctx, spec.User, installAndFind)
		if findErr == nil {
			// nvm which may print multiple lines; take the last one that looks like a path
			for _, line := range strings.Split(nodePath, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/node") {
					interpreterFlag = " --interpreter " + shellQuote(line)
				}
			}
		}
		if interpreterFlag == "" {
			// fallback: set nvm use so at least the current invocation is correct
			interpreterFlag = ""
		}
	}

	pm2Command := ""
	if spec.NodeVersion != "" && interpreterFlag == "" {
		// Could not resolve exact path; fall back to nvm use (best-effort)
		pm2Command += "nvm install " + shellQuote(spec.NodeVersion) + " && nvm use " + shellQuote(spec.NodeVersion) + " && "
	}
	pm2Command += "cd " + shellQuote(spec.WorkingDirectory)
	pm2Command += " && pm2 delete " + shellQuote(spec.ProcessName) + " >/dev/null 2>&1 || true"
	pm2Command += " && pm2 start " + shellQuote(resolvedScriptPath) + " --name " + shellQuote(spec.ProcessName) + " --cwd " + shellQuote(spec.WorkingDirectory) + interpreterFlag
	if spec.Arguments != "" {
		pm2Command += " -- " + shellJoin(strings.Fields(spec.Arguments))
	}
	pm2Command += " && pm2 save"
	return runBashAsUser(ctx, spec.User, buildNVMCommand(homeDirectory, pm2Command))
}

func resolvePM2ScriptPath(workingDirectory string, scriptPath string) (string, error) {
	if filepath.IsAbs(scriptPath) {
		if _, err := os.Stat(scriptPath); err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("PM2 start script was not found: %s", scriptPath)
			}
			return "", err
		}
		return scriptPath, nil
	}
	resolvedPath := filepath.Join(workingDirectory, scriptPath)
	if _, err := os.Stat(resolvedPath); err == nil {
		return scriptPath, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if scriptPath == "ecosystem.config.cjs" {
		fallbackPath := filepath.Join(workingDirectory, "ecosystem.config.js")
		if _, err := os.Stat(fallbackPath); err == nil {
			return "", fmt.Errorf("PM2 start script was not found: %s. Found ecosystem.config.js in the subdomain root; use that file instead", scriptPath)
		}
	}
	return "", fmt.Errorf("PM2 start script was not found: %s", scriptPath)
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

func StreamCustomRuntimeCommand(spec CustomRuntimeCommandSpec, stdout io.Writer, stderr io.Writer) error {
	spec.User = strings.TrimSpace(spec.User)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.CommandBody = strings.TrimSpace(spec.CommandBody)
	spec.NodeVersion = strings.TrimSpace(spec.NodeVersion)
	if !usernamePattern.MatchString(spec.User) {
		return ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return ErrInvalidTargetDirectory
	}
	if spec.CommandBody == "" {
		return fmt.Errorf("custom command cannot be empty")
	}
	if len(spec.CommandBody) > 16000 {
		return fmt.Errorf("custom command is too long")
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
	command := "cd " + shellQuote(spec.WorkingDirectory) + " && " + spec.CommandBody
	if spec.NodeVersion != "" {
		command = "nvm use " + shellQuote(spec.NodeVersion) + " && " + command
		return runBashAsUserStream(ctx, spec.User, buildNVMCommand(homeDirectory, command), stdout, stderr)
	}
	return runBashAsUserStream(ctx, spec.User, buildShellWithOptionalNVM(homeDirectory, command), stdout, stderr)
}

func StreamShellCommand(spec ShellCommandSpec, stdout io.Writer, stderr io.Writer) error {
	spec.User = strings.TrimSpace(spec.User)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.CommandBody = strings.TrimSpace(spec.CommandBody)
	if !usernamePattern.MatchString(spec.User) {
		return ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return ErrInvalidTargetDirectory
	}
	if spec.CommandBody == "" {
		return fmt.Errorf("shell command cannot be empty")
	}
	if len(spec.CommandBody) > 16000 {
		return fmt.Errorf("shell command is too long")
	}
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	command := "cd " + shellQuote(spec.WorkingDirectory) + " && " + spec.CommandBody
	return runBashAsUserStream(ctx, spec.User, buildShellWithOptionalNVM(homeDirectory, command), stdout, stderr)
}

func StreamInstallComposer(stdout io.Writer, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runBashAsRootStream(ctx, composerInstallScript(), stdout, stderr)
}

func StreamFixLaravelPermissions(rootDir string, ownerUser string, extraWritablePaths []string, stdout io.Writer, stderr io.Writer) error {
	ownerUser = strings.TrimSpace(ownerUser)
	rootDir = strings.TrimSpace(rootDir)
	if !usernamePattern.MatchString(ownerUser) {
		return ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(rootDir) {
		return ErrInvalidTargetDirectory
	}
	normalizedExtraPaths, err := normalizeLaravelWritablePaths(extraWritablePaths)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	scriptLines := []string{
		"set -eu",
		"cd " + shellQuote(rootDir),
		"echo 'Checking Laravel directories'",
		"mkdir -p storage/logs storage/framework/cache storage/framework/sessions storage/framework/views bootstrap/cache",
		"if [ -d vendor/mpdf/mpdf ]; then mkdir -p vendor/mpdf/mpdf/tmp/mpdf; fi",
		"touch storage/logs/laravel.log",
		"echo 'Fixing base ownership'",
		"chown -R " + shellQuote(ownerUser+":"+ownerUser) + " .",
		"echo 'Setting base directory permissions'",
		"find . -path './.git' -prune -o -type d -print -exec chmod 755 {} \\;",
		"find . -path './.git' -prune -o -type f -print -exec chmod 644 {} \\;",
		"echo 'Applying writable Laravel directories for owner and PHP-FPM'",
		"chown -R " + shellQuote(ownerUser+":www-data") + " storage bootstrap/cache",
		"chmod -R ug+rwX storage bootstrap/cache",
		"find storage bootstrap/cache -type d -print -exec chmod 2775 {} \\;",
		"find storage bootstrap/cache -type f -print -exec chmod 664 {} \\;",
		"if command -v setfacl >/dev/null 2>&1; then setfacl -R -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage bootstrap/cache; setfacl -R -d -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage bootstrap/cache; else echo 'setfacl not found; continuing with chmod/chown fallback'; fi",
		"echo 'Hardening Laravel log directory permissions'",
		"mkdir -p storage/logs",
		"touch storage/logs/laravel.log",
		"chown " + shellQuote(ownerUser+":www-data") + " storage/logs storage/logs/laravel.log",
		"chmod 2775 storage/logs",
		"chmod 664 storage/logs/laravel.log",
		"if command -v setfacl >/dev/null 2>&1; then setfacl -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage/logs; setfacl -d -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage/logs; setfacl -m u:" + ownerUser + ":rw -m u:www-data:rw storage/logs/laravel.log; fi",
		"if find storage -maxdepth 1 -type f -name 'oauth-p*' | grep -q .; then echo 'Securing Laravel oauth key files'; find storage -maxdepth 1 -type f -name 'oauth-p*' -print -exec chmod 640 {} \\;; fi",
		"if [ -d vendor/mpdf/mpdf/tmp ]; then echo 'Applying writable mPDF temp directories'; chown -R " + shellQuote(ownerUser+":www-data") + " vendor/mpdf/mpdf/tmp; chmod -R ug+rwX vendor/mpdf/mpdf/tmp; find vendor/mpdf/mpdf/tmp -type d -print -exec chmod 2775 {} \\;; find vendor/mpdf/mpdf/tmp -type f -print -exec chmod 664 {} \\;; if command -v setfacl >/dev/null 2>&1; then setfacl -R -m u:" + ownerUser + ":rwx -m u:www-data:rwx vendor/mpdf/mpdf/tmp; setfacl -R -d -m u:" + ownerUser + ":rwx -m u:www-data:rwx vendor/mpdf/mpdf/tmp; fi; fi",
	}
	for _, path := range normalizedExtraPaths {
		scriptLines = append(scriptLines,
			"echo 'Applying extra writable path: "+path+"'",
			"mkdir -p "+shellQuote(path),
			"chown -R "+shellQuote(ownerUser+":www-data")+" "+shellQuote(path),
			"chmod -R ug+rwX "+shellQuote(path),
			"find "+shellQuote(path)+" -type d -print -exec chmod 2775 {} \\;",
			"find "+shellQuote(path)+" -type f -print -exec chmod 664 {} \\;",
			"if command -v setfacl >/dev/null 2>&1; then setfacl -R -m u:"+ownerUser+":rwx -m u:www-data:rwx "+shellQuote(path)+"; setfacl -R -d -m u:"+ownerUser+":rwx -m u:www-data:rwx "+shellQuote(path)+"; else echo 'setfacl not found; continuing with chmod/chown fallback'; fi",
		)
	}
	scriptLines = append(scriptLines, "echo 'Laravel permissions updated successfully.'")
	script := strings.Join(scriptLines, "\n")
	return runBashAsRootStream(ctx, script, stdout, stderr)
}

func normalizeLaravelWritablePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(paths))
	normalized := make([]string, 0, len(paths))
	for _, raw := range paths {
		path := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
		path = strings.TrimPrefix(path, "./")
		if path == "" {
			continue
		}
		cleaned := filepath.Clean(path)
		cleaned = strings.ReplaceAll(cleaned, "\\", "/")
		if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || filepath.IsAbs(cleaned) {
			return nil, fmt.Errorf("invalid extra writable path: %s", raw)
		}
		if _, exists := seen[cleaned]; exists {
			continue
		}
		seen[cleaned] = struct{}{}
		normalized = append(normalized, cleaned)
	}
	return normalized, nil
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

func runBashAsRoot(ctx context.Context, script string) (string, error) {
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, "bash", "-lc", script)
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

func runBashAsRootStream(ctx context.Context, script string, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = stdout
	}
	cmd := exec.CommandContext(ctx, "bash", "-lc", script)
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

func listAvailableNodeVersions(user string, homeDirectory string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := runBashAsUser(ctx, user, buildNVMCommand(homeDirectory, "nvm ls-remote --no-colors"))
	if err != nil {
		return commonNodeVersionChoices()
	}
	versions := installedNodePattern.FindAllString(output, -1)
	if len(versions) == 0 {
		return commonNodeVersionChoices()
	}
	latestByMajor := make(map[int][3]int)
	for _, version := range versions {
		parsed, ok := parseNodeVersion(version)
		if !ok {
			continue
		}
		current, exists := latestByMajor[parsed[0]]
		if !exists || compareNodeVersionParts(parsed, current) > 0 {
			latestByMajor[parsed[0]] = parsed
		}
	}
	if len(latestByMajor) == 0 {
		return commonNodeVersionChoices()
	}
	majors := make([]int, 0, len(latestByMajor))
	for major := range latestByMajor {
		majors = append(majors, major)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(majors)))
	available := make([]string, 0, len(majors))
	for _, major := range majors {
		parts := latestByMajor[major]
		available = append(available, fmt.Sprintf("v%d.%d.%d", parts[0], parts[1], parts[2]))
	}
	return available
}

func parseNodeVersion(raw string) ([3]int, bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "v"))
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return [3]int{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return [3]int{}, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return [3]int{}, false
	}
	return [3]int{major, minor, patch}, true
}

func compareNodeVersionParts(left [3]int, right [3]int) int {
	for index := 0; index < len(left); index++ {
		if left[index] == right[index] {
			continue
		}
		if left[index] > right[index] {
			return 1
		}
		return -1
	}
	return 0
}

func commonNodeVersionChoices() []string {
	return []string{"node", "lts/*", "22", "20", "18", "16", "14", "12", "10", "8.17.0"}
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

func composerInstallScript() string {
	return strings.Join([]string{
		"set -e",
		"if command -v composer >/dev/null 2>&1; then composer --version --no-ansi; exit 0; fi",
		"if ! command -v php >/dev/null 2>&1; then echo 'php-cli is required to install Composer'; exit 1; fi",
		"if command -v curl >/dev/null 2>&1; then FETCH='curl -fsSL'; elif command -v wget >/dev/null 2>&1; then FETCH='wget -qO-'; else echo 'curl or wget is required to install Composer'; exit 1; fi",
		"tmp_dir=$(mktemp -d)",
		"trap 'rm -rf \"$tmp_dir\"' EXIT",
		"cd \"$tmp_dir\"",
		"expected_signature=$($FETCH https://composer.github.io/installer.sig)",
		"php -r \"copy('https://getcomposer.org/installer', 'composer-setup.php');\"",
		"actual_signature=$(php -r \"echo hash_file('sha384', 'composer-setup.php');\")",
		"if [ \"$expected_signature\" != \"$actual_signature\" ]; then echo 'Composer installer signature verification failed'; exit 1; fi",
		"php composer-setup.php --no-ansi --install-dir=/usr/local/bin --filename=composer",
		"composer --version --no-ansi",
	}, "; ")
}
