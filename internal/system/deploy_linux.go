//go:build linux

package system

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var repoURLPattern = regexp.MustCompile(`^(https://|git@)[^\s]+$`)
var branchPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

type linuxDeployManager struct{}

func NewDeployManager() DeployManager {
	return linuxDeployManager{}
}

func (linuxDeployManager) Deploy(spec DeploySpec) (DeployResult, error) {
	spec.RepositoryURL = strings.TrimSpace(spec.RepositoryURL)
	spec.Branch = strings.TrimSpace(spec.Branch)
	spec.TargetDirectory = strings.TrimSpace(spec.TargetDirectory)
	spec.RunAsUser = strings.TrimSpace(spec.RunAsUser)
	spec.GitSiteName = strings.TrimSpace(spec.GitSiteName)
	spec.PostDeployNodeVersion = strings.TrimSpace(spec.PostDeployNodeVersion)

	if !repoURLPattern.MatchString(spec.RepositoryURL) {
		return DeployResult{}, ErrInvalidRepoURL
	}
	if spec.Branch != "" && !branchPattern.MatchString(spec.Branch) {
		return DeployResult{}, ErrInvalidBranch
	}
	if !filepath.IsAbs(spec.TargetDirectory) {
		return DeployResult{}, ErrInvalidTargetDirectory
	}
	if !usernamePattern.MatchString(spec.RunAsUser) {
		return DeployResult{}, ErrInvalidRunAsUser
	}
	if spec.PostDeployNodeVersion != "" && !nodeVersionPattern.MatchString(spec.PostDeployNodeVersion) {
		return DeployResult{}, ErrInvalidNodeVersion
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := os.MkdirAll(filepath.Dir(spec.TargetDirectory), 0o755); err != nil {
		return DeployResult{}, err
	}

	gitEnv, sshConfigErr := gitEnvironmentForDeploy(spec)
	if sshConfigErr != nil {
		return DeployResult{}, sshConfigErr
	}
	resolvedBranch, resolveErr := resolveDeployBranch(ctx, spec, gitEnv, nil)
	if resolveErr != nil {
		return DeployResult{}, resolveErr
	}
	spec.Branch = resolvedBranch

	var output bytes.Buffer
	action := "clone"
	previousCommit, _ := currentCommit(ctx, spec.RunAsUser, spec.TargetDirectory, &output)
	if dirExists(filepath.Join(spec.TargetDirectory, ".git")) {
		action = "update"
		if err := configureRepositorySSHCommand(ctx, spec.RunAsUser, spec.TargetDirectory, gitEnv, &output); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := configureRepositoryFileMode(ctx, spec.RunAsUser, spec.TargetDirectory, &output); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := runAsUserEnv(ctx, spec.RunAsUser, gitEnv, &output, "git", "-C", spec.TargetDirectory, "fetch", "--all", "--prune"); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := ensureCleanGitWorktree(ctx, spec.RunAsUser, spec.TargetDirectory, &output); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := runAsUserEnv(ctx, spec.RunAsUser, gitEnv, &output, "git", "-C", spec.TargetDirectory, "checkout", spec.Branch); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := runAsUserEnv(ctx, spec.RunAsUser, gitEnv, &output, "git", "-C", spec.TargetDirectory, "pull", "--ff-only", "origin", spec.Branch); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
	} else {
		if err := runAsUserEnv(ctx, spec.RunAsUser, gitEnv, &output, "git", "clone", "--branch", spec.Branch, spec.RepositoryURL, spec.TargetDirectory); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := configureRepositorySSHCommand(ctx, spec.RunAsUser, spec.TargetDirectory, gitEnv, &output); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := configureRepositoryFileMode(ctx, spec.RunAsUser, spec.TargetDirectory, &output); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
	}

	commitSHA, err := currentCommit(ctx, spec.RunAsUser, spec.TargetDirectory, &output)
	if err != nil {
		return DeployResult{Action: action, Output: output.String(), PreviousCommitSHA: previousCommit}, err
	}

	if strings.TrimSpace(spec.PostDeployCommand) != "" {
		action = action + " + post-deploy"
		if err := runShellAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, spec.PostDeployCommand, spec.PostDeployNodeVersion, &output); err != nil {
			return DeployResult{Action: action, Output: output.String(), CommitSHA: commitSHA, PreviousCommitSHA: previousCommit}, err
		}
	}

	return DeployResult{Action: action, Output: strings.TrimSpace(output.String()), CommitSHA: commitSHA, PreviousCommitSHA: previousCommit}, nil
}

func (linuxDeployManager) Rollback(spec RollbackSpec) (DeployResult, error) {
	spec.TargetDirectory = strings.TrimSpace(spec.TargetDirectory)
	spec.RunAsUser = strings.TrimSpace(spec.RunAsUser)
	spec.ReleaseCommitSHA = strings.TrimSpace(spec.ReleaseCommitSHA)
	if !filepath.IsAbs(spec.TargetDirectory) {
		return DeployResult{}, ErrInvalidTargetDirectory
	}
	if !usernamePattern.MatchString(spec.RunAsUser) {
		return DeployResult{}, ErrInvalidRunAsUser
	}
	if spec.ReleaseCommitSHA == "" || !branchPattern.MatchString(spec.ReleaseCommitSHA) {
		return DeployResult{}, ErrInvalidBranch
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var output bytes.Buffer
	previousCommit, _ := currentCommit(ctx, spec.RunAsUser, spec.TargetDirectory, &output)
	if err := runAsUser(ctx, spec.RunAsUser, &output, "git", "-C", spec.TargetDirectory, "rev-parse", "--verify", spec.ReleaseCommitSHA+"^{commit}"); err != nil {
		return DeployResult{Action: "rollback", Output: output.String(), PreviousCommitSHA: previousCommit}, err
	}
	if err := runAsUser(ctx, spec.RunAsUser, &output, "git", "-C", spec.TargetDirectory, "reset", "--hard", spec.ReleaseCommitSHA); err != nil {
		return DeployResult{Action: "rollback", Output: output.String(), PreviousCommitSHA: previousCommit}, err
	}
	if strings.TrimSpace(spec.PostDeployCommand) != "" {
		if err := runShellAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, spec.PostDeployCommand, "", &output); err != nil {
			return DeployResult{Action: "rollback + post-deploy", Output: output.String(), PreviousCommitSHA: previousCommit, CommitSHA: spec.ReleaseCommitSHA}, err
		}
	}
	commitSHA, err := currentCommit(ctx, spec.RunAsUser, spec.TargetDirectory, &output)
	if err != nil {
		return DeployResult{Action: "rollback", Output: output.String(), PreviousCommitSHA: previousCommit}, err
	}
	return DeployResult{Action: "rollback", Output: strings.TrimSpace(output.String()), CommitSHA: commitSHA, PreviousCommitSHA: previousCommit}, nil
}

func (linuxDeployManager) Inspect(spec RepositoryInspectSpec) (RepositoryStatus, error) {
	spec.TargetDirectory = strings.TrimSpace(spec.TargetDirectory)
	spec.RunAsUser = strings.TrimSpace(spec.RunAsUser)
	if !filepath.IsAbs(spec.TargetDirectory) {
		return RepositoryStatus{}, ErrInvalidTargetDirectory
	}
	if !usernamePattern.MatchString(spec.RunAsUser) {
		return RepositoryStatus{}, ErrInvalidRunAsUser
	}

	status := RepositoryStatus{
		TargetDirectory: spec.TargetDirectory,
		RunAsUser:       spec.RunAsUser,
	}
	if !dirExists(spec.TargetDirectory) {
		return status, nil
	}
	status.DirectoryExists = true
	if !dirExists(filepath.Join(spec.TargetDirectory, ".git")) {
		return status, nil
	}
	status.IsGitRepo = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status.RemoteURL = strings.TrimSpace(commandOutputAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, "config", "--get", "remote.origin.url"))
	status.Branch = strings.TrimSpace(commandOutputAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, "rev-parse", "--abbrev-ref", "HEAD"))
	status.CurrentCommit = strings.TrimSpace(commandOutputAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, "rev-parse", "HEAD"))
	return status, nil
}

func StreamDeploy(spec DeploySpec, stdout io.Writer, stderr io.Writer) error {
	spec.RepositoryURL = strings.TrimSpace(spec.RepositoryURL)
	spec.Branch = strings.TrimSpace(spec.Branch)
	spec.TargetDirectory = strings.TrimSpace(spec.TargetDirectory)
	spec.RunAsUser = strings.TrimSpace(spec.RunAsUser)
	spec.GitSiteName = strings.TrimSpace(spec.GitSiteName)
	spec.PostDeployNodeVersion = strings.TrimSpace(spec.PostDeployNodeVersion)

	if !repoURLPattern.MatchString(spec.RepositoryURL) {
		return ErrInvalidRepoURL
	}
	if spec.Branch != "" && !branchPattern.MatchString(spec.Branch) {
		return ErrInvalidBranch
	}
	if !filepath.IsAbs(spec.TargetDirectory) {
		return ErrInvalidTargetDirectory
	}
	if !usernamePattern.MatchString(spec.RunAsUser) {
		return ErrInvalidRunAsUser
	}
	if spec.PostDeployNodeVersion != "" && !nodeVersionPattern.MatchString(spec.PostDeployNodeVersion) {
		return ErrInvalidNodeVersion
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := os.MkdirAll(filepath.Dir(spec.TargetDirectory), 0o755); err != nil {
		return err
	}

	gitEnv, sshConfigErr := gitEnvironmentForDeploy(spec)
	if sshConfigErr != nil {
		return sshConfigErr
	}
	resolvedBranch, resolveErr := resolveDeployBranch(ctx, spec, gitEnv, stdout)
	if resolveErr != nil {
		return resolveErr
	}
	spec.Branch = resolvedBranch

	if dirExists(filepath.Join(spec.TargetDirectory, ".git")) {
		if err := configureRepositorySSHCommandStream(ctx, spec.RunAsUser, spec.TargetDirectory, gitEnv, stdout, stderr); err != nil {
			return err
		}
		if err := configureRepositoryFileModeStream(ctx, spec.RunAsUser, spec.TargetDirectory, stdout, stderr); err != nil {
			return err
		}
		if err := runAsUserStreamEnv(ctx, spec.RunAsUser, gitEnv, stdout, stderr, "git", "-C", spec.TargetDirectory, "fetch", "--all", "--prune"); err != nil {
			return err
		}
		if err := ensureCleanGitWorktreeStream(ctx, spec.RunAsUser, spec.TargetDirectory, stdout, stderr); err != nil {
			return err
		}
		if err := runAsUserStreamEnv(ctx, spec.RunAsUser, gitEnv, stdout, stderr, "git", "-C", spec.TargetDirectory, "checkout", spec.Branch); err != nil {
			return err
		}
		if err := runAsUserStreamEnv(ctx, spec.RunAsUser, gitEnv, stdout, stderr, "git", "-C", spec.TargetDirectory, "pull", "--ff-only", "origin", spec.Branch); err != nil {
			return err
		}
	} else {
		if err := runAsUserStreamEnv(ctx, spec.RunAsUser, gitEnv, stdout, stderr, "git", "clone", "--branch", spec.Branch, spec.RepositoryURL, spec.TargetDirectory); err != nil {
			return err
		}
		if err := configureRepositorySSHCommandStream(ctx, spec.RunAsUser, spec.TargetDirectory, gitEnv, stdout, stderr); err != nil {
			return err
		}
		if err := configureRepositoryFileModeStream(ctx, spec.RunAsUser, spec.TargetDirectory, stdout, stderr); err != nil {
			return err
		}
	}

	if strings.TrimSpace(spec.PostDeployCommand) != "" {
		return runShellAsUserStream(ctx, spec.RunAsUser, spec.TargetDirectory, spec.PostDeployCommand, spec.PostDeployNodeVersion, stdout, stderr)
	}
	return nil
}

func StreamGitCommand(spec GitCommandSpec, stdout io.Writer, stderr io.Writer) error {
	spec.User = strings.TrimSpace(spec.User)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	spec.Command = strings.TrimSpace(spec.Command)
	if !usernamePattern.MatchString(spec.User) {
		return ErrInvalidRunAsUser
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return ErrInvalidTargetDirectory
	}
	if err := ValidateGitCommand(spec.Command); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return runShellAsUserStream(ctx, spec.User, spec.WorkingDirectory, spec.Command, "", stdout, stderr)
}

func currentCommit(ctx context.Context, username string, directory string, output *bytes.Buffer) (string, error) {
	if !dirExists(filepath.Join(directory, ".git")) {
		return "", nil
	}
	var localOutput bytes.Buffer
	if err := runAsUser(ctx, username, &localOutput, "git", "-C", directory, "rev-parse", "HEAD"); err != nil {
		if output != nil {
			output.Write(localOutput.Bytes())
		}
		return "", err
	}
	if output != nil {
		output.Write(localOutput.Bytes())
	}
	return strings.TrimSpace(localOutput.String()), nil
}

func currentBranch(ctx context.Context, username string, directory string, output *bytes.Buffer) (string, error) {
	if !dirExists(filepath.Join(directory, ".git")) {
		return "", nil
	}
	var localOutput bytes.Buffer
	if err := runAsUser(ctx, username, &localOutput, "git", "-C", directory, "rev-parse", "--abbrev-ref", "HEAD"); err != nil {
		if output != nil {
			output.Write(localOutput.Bytes())
		}
		return "", err
	}
	if output != nil {
		output.Write(localOutput.Bytes())
	}
	branch := strings.TrimSpace(localOutput.String())
	if branch == "HEAD" {
		return "", nil
	}
	return branch, nil
}

func resolveDeployBranch(ctx context.Context, spec DeploySpec, env map[string]string, output io.Writer) (string, error) {
	if spec.Branch != "" {
		if branchExistsRemote(ctx, spec.RunAsUser, spec.RepositoryURL, spec.Branch, env, output) {
			return spec.Branch, nil
		}
		if current := strings.TrimSpace(commandOutputAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, "rev-parse", "--abbrev-ref", "HEAD")); current != "" && current != "HEAD" {
			return current, nil
		}
		if remote := strings.TrimSpace(detectRemoteDefaultBranch(ctx, spec.RunAsUser, spec.RepositoryURL, env, output)); remote != "" {
			return remote, nil
		}
		return spec.Branch, nil
	}
	if current := strings.TrimSpace(commandOutputAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, "rev-parse", "--abbrev-ref", "HEAD")); current != "" && current != "HEAD" {
		return current, nil
	}
	if remote := strings.TrimSpace(detectRemoteDefaultBranch(ctx, spec.RunAsUser, spec.RepositoryURL, env, output)); remote != "" {
		return remote, nil
	}
	return "main", nil
}

func detectRemoteDefaultBranch(ctx context.Context, username string, repositoryURL string, env map[string]string, output io.Writer) string {
	var buffer bytes.Buffer
	if err := runAsUserEnv(ctx, username, env, &buffer, "git", "ls-remote", "--symref", repositoryURL, "HEAD"); err == nil {
		if output != nil {
			_, _ = output.Write(buffer.Bytes())
		}
		for _, line := range strings.Split(buffer.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ref:") && strings.HasSuffix(line, "HEAD") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ref := strings.TrimSpace(fields[1])
					if strings.HasPrefix(ref, "refs/heads/") {
						return strings.TrimPrefix(ref, "refs/heads/")
					}
				}
			}
		}
	}
	for _, candidate := range []string{"main", "master"} {
		buffer.Reset()
		if err := runAsUserEnv(ctx, username, env, &buffer, "git", "ls-remote", "--heads", repositoryURL, candidate); err == nil {
			if output != nil {
				_, _ = output.Write(buffer.Bytes())
			}
			if strings.TrimSpace(buffer.String()) != "" {
				return candidate
			}
		}
	}
	return ""
}

func branchExistsRemote(ctx context.Context, username string, repositoryURL string, branch string, env map[string]string, output io.Writer) bool {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return false
	}
	var buffer bytes.Buffer
	if err := runAsUserEnv(ctx, username, env, &buffer, "git", "ls-remote", "--heads", repositoryURL, branch); err != nil {
		return false
	}
	if output != nil {
		_, _ = output.Write(buffer.Bytes())
	}
	return strings.TrimSpace(buffer.String()) != ""
}

func commandOutputAsUser(ctx context.Context, username string, directory string, args ...string) string {
	var output bytes.Buffer
	commandArgs := append([]string{"-C", directory}, args...)
	if err := runAsUser(ctx, username, &output, "git", commandArgs...); err != nil {
		return ""
	}
	return output.String()
}

func runAsUser(ctx context.Context, username string, output *bytes.Buffer, name string, args ...string) error {
	return runAsUserEnv(ctx, username, nil, output, name, args...)
}

func runAsUserEnv(ctx context.Context, username string, env map[string]string, output *bytes.Buffer, name string, args ...string) error {
	fullArgs := buildSudoCommandArgs(username, env, name, args...)
	cmd := exec.CommandContext(ctx, "sudo", fullArgs...)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

func runAsUserStream(ctx context.Context, username string, stdout io.Writer, stderr io.Writer, name string, args ...string) error {
	return runAsUserStreamEnv(ctx, username, nil, stdout, stderr, name, args...)
}

func runAsUserStreamEnv(ctx context.Context, username string, env map[string]string, stdout io.Writer, stderr io.Writer, name string, args ...string) error {
	fullArgs := buildSudoCommandArgs(username, env, name, args...)
	cmd := exec.CommandContext(ctx, "sudo", fullArgs...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

func buildSudoCommandArgs(username string, env map[string]string, name string, args ...string) []string {
	fullArgs := append([]string{"-u", username, "--", name}, args...)
	if len(env) == 0 {
		return fullArgs
	}
	envArgs := make([]string, 0, len(env))
	for key, value := range env {
		envArgs = append(envArgs, key+"="+value)
	}
	fullArgs = append([]string{"-u", username, "--", "env"}, envArgs...)
	fullArgs = append(fullArgs, name)
	fullArgs = append(fullArgs, args...)
	return fullArgs
}

func gitEnvironmentForDeploy(spec DeploySpec) (map[string]string, error) {
	protocol, _ := parseRepositoryEndpoint(spec.RepositoryURL)
	if protocol != "ssh" || spec.GitSiteName == "" {
		return nil, nil
	}
	homeDirectory, err := lookupUserHome(spec.RunAsUser)
	if err != nil {
		return nil, err
	}
	keyPath := deployKeyBasePath(homeDirectory, spec.GitSiteName)
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("deploy key not found for %s", spec.GitSiteName)
		}
		return nil, err
	}
	return map[string]string{
		"GIT_SSH_COMMAND": buildGitSSHCommand(keyPath),
		"GIT_TERMINAL_PROMPT": "0",
	}, nil
}

func buildGitSSHCommand(keyPath string) string {
	return fmt.Sprintf("ssh -F /dev/null -i %s -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=yes", shellQuote(keyPath))
}

func configureRepositorySSHCommand(ctx context.Context, username string, targetDirectory string, env map[string]string, output *bytes.Buffer) error {
	sshCommand := strings.TrimSpace(envValue(env, "GIT_SSH_COMMAND"))
	if sshCommand == "" {
		return nil
	}
	return runAsUser(ctx, username, output, "git", "-C", targetDirectory, "config", "core.sshCommand", sshCommand)
}

func configureRepositorySSHCommandStream(ctx context.Context, username string, targetDirectory string, env map[string]string, stdout io.Writer, stderr io.Writer) error {
	sshCommand := strings.TrimSpace(envValue(env, "GIT_SSH_COMMAND"))
	if sshCommand == "" {
		return nil
	}
	return runAsUserStream(ctx, username, stdout, stderr, "git", "-C", targetDirectory, "config", "core.sshCommand", sshCommand)
}

func configureRepositoryFileMode(ctx context.Context, username string, targetDirectory string, output *bytes.Buffer) error {
	return runAsUser(ctx, username, output, "git", "-C", targetDirectory, "config", "core.fileMode", "false")
}

func configureRepositoryFileModeStream(ctx context.Context, username string, targetDirectory string, stdout io.Writer, stderr io.Writer) error {
	return runAsUserStream(ctx, username, stdout, stderr, "git", "-C", targetDirectory, "config", "core.fileMode", "false")
}

func ensureCleanGitWorktree(ctx context.Context, username string, targetDirectory string, output *bytes.Buffer) error {
	var statusOutput bytes.Buffer
	if err := runAsUser(ctx, username, &statusOutput, "git", "-C", targetDirectory, "status", "--porcelain", "--untracked-files=no"); err != nil {
		if output != nil {
			output.Write(statusOutput.Bytes())
		}
		return err
	}
	if output != nil {
		output.Write(statusOutput.Bytes())
	}
	files := filterIgnoredDirtyWorktreeFiles(parseDirtyWorktreeFiles(statusOutput.String()))
	if len(files) == 0 {
		return nil
	}
	if output != nil {
		output.WriteString("deploy blocked: local git changes detected in: " + strings.Join(files, ", ") + "\n")
	}
	return fmt.Errorf("%w: %s", ErrDirtyWorkingTree, strings.Join(files, ", "))
}

func ensureCleanGitWorktreeStream(ctx context.Context, username string, targetDirectory string, stdout io.Writer, stderr io.Writer) error {
	var statusOutput bytes.Buffer
	if err := runAsUser(ctx, username, &statusOutput, "git", "-C", targetDirectory, "status", "--porcelain", "--untracked-files=no"); err != nil {
		if stdout != nil {
			_, _ = stdout.Write(statusOutput.Bytes())
		}
		return err
	}
	if stdout != nil {
		_, _ = stdout.Write(statusOutput.Bytes())
	}
	files := filterIgnoredDirtyWorktreeFiles(parseDirtyWorktreeFiles(statusOutput.String()))
	if len(files) == 0 {
		return nil
	}
	message := "deploy blocked: local git changes detected in: " + strings.Join(files, ", ") + "\n"
	if stderr != nil {
		_, _ = io.WriteString(stderr, message)
	}
	return fmt.Errorf("%w: %s", ErrDirtyWorkingTree, strings.Join(files, ", "))
}

func parseDirtyWorktreeFiles(output string) []string {
	files := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		if path == "" {
			continue
		}
		if parts := strings.SplitN(path, " -> ", 2); len(parts) == 2 {
			path = strings.TrimSpace(parts[1])
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		files = append(files, path)
	}
	return files
}

func filterIgnoredDirtyWorktreeFiles(files []string) []string {
	filtered := make([]string, 0, len(files))
	for _, path := range files {
		if shouldIgnoreDirtyWorktreePath(path) {
			continue
		}
		filtered = append(filtered, path)
	}
	return filtered
}

func shouldIgnoreDirtyWorktreePath(path string) bool {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return false
	}
	base := filepath.Base(trimmed)
	switch base {
	case "build-info.json":
		return true
	default:
		return false
	}
}

func envValue(env map[string]string, key string) string {
	if len(env) == 0 {
		return ""
	}
	return env[key]
}

func runShellAsUser(ctx context.Context, username string, workingDir string, command string, nodeVersion string, output *bytes.Buffer) error {
	homeDirectory, err := lookupUserHome(username)
	if err != nil {
		return err
	}
	shellCommand := "cd " + shellQuote(workingDir) + " && " + command
	if strings.TrimSpace(nodeVersion) != "" {
		shellCommand = "nvm install " + shellQuote(strings.TrimSpace(nodeVersion)) + " && nvm use " + shellQuote(strings.TrimSpace(nodeVersion)) + " && " + shellCommand
		shellCommand = buildNVMCommand(homeDirectory, shellCommand)
	} else {
		shellCommand = buildShellWithOptionalNVM(homeDirectory, shellCommand)
	}
	cmd := exec.CommandContext(ctx, "sudo", "-u", username, "--", "bash", "-lc", shellCommand)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("post-deploy command failed: %w", err)
	}
	return nil
}

func runShellAsUserStream(ctx context.Context, username string, workingDir string, command string, nodeVersion string, stdout io.Writer, stderr io.Writer) error {
	homeDirectory, err := lookupUserHome(username)
	if err != nil {
		return err
	}
	shellCommand := "cd " + shellQuote(workingDir) + " && " + command
	if strings.TrimSpace(nodeVersion) != "" {
		shellCommand = "nvm install " + shellQuote(strings.TrimSpace(nodeVersion)) + " && nvm use " + shellQuote(strings.TrimSpace(nodeVersion)) + " && " + shellCommand
		shellCommand = buildNVMCommand(homeDirectory, shellCommand)
	} else {
		shellCommand = buildShellWithOptionalNVM(homeDirectory, shellCommand)
	}
	cmd := exec.CommandContext(ctx, "sudo", "-u", username, "--", "bash", "-lc", shellCommand)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("post-deploy command failed: %w", err)
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
