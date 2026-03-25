//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var repoURLPattern = regexp.MustCompile(`^(https://|git@)[^\s]+$`)
var branchPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

var ErrInvalidRepoURL = errors.New("invalid git repository url")
var ErrInvalidBranch = errors.New("invalid branch name")
var ErrInvalidTargetDirectory = errors.New("invalid target directory")
var ErrInvalidRunAsUser = errors.New("invalid run-as user")

type DeploySpec struct {
	RepositoryURL    string
	Branch           string
	TargetDirectory  string
	RunAsUser        string
	PostDeployCommand string
}

type RollbackSpec struct {
	TargetDirectory   string
	RunAsUser         string
	ReleaseCommitSHA  string
	PostDeployCommand string
}

type DeployResult struct {
	Action            string
	Output            string
	CommitSHA         string
	PreviousCommitSHA string
}

type DeployManager interface {
	Deploy(spec DeploySpec) (DeployResult, error)
	Rollback(spec RollbackSpec) (DeployResult, error)
}

type linuxDeployManager struct{}

func NewDeployManager() DeployManager {
	return linuxDeployManager{}
}

func (linuxDeployManager) Deploy(spec DeploySpec) (DeployResult, error) {
	spec.RepositoryURL = strings.TrimSpace(spec.RepositoryURL)
	spec.Branch = strings.TrimSpace(spec.Branch)
	spec.TargetDirectory = strings.TrimSpace(spec.TargetDirectory)
	spec.RunAsUser = strings.TrimSpace(spec.RunAsUser)
	if spec.Branch == "" {
		spec.Branch = "main"
	}

	if !repoURLPattern.MatchString(spec.RepositoryURL) {
		return DeployResult{}, ErrInvalidRepoURL
	}
	if !branchPattern.MatchString(spec.Branch) {
		return DeployResult{}, ErrInvalidBranch
	}
	if !filepath.IsAbs(spec.TargetDirectory) {
		return DeployResult{}, ErrInvalidTargetDirectory
	}
	if !usernamePattern.MatchString(spec.RunAsUser) {
		return DeployResult{}, ErrInvalidRunAsUser
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := os.MkdirAll(filepath.Dir(spec.TargetDirectory), 0o755); err != nil {
		return DeployResult{}, err
	}

	var output bytes.Buffer
	action := "clone"
	previousCommit, _ := currentCommit(ctx, spec.RunAsUser, spec.TargetDirectory, &output)
	if dirExists(filepath.Join(spec.TargetDirectory, ".git")) {
		action = "update"
		if err := runAsUser(ctx, spec.RunAsUser, &output, "git", "-C", spec.TargetDirectory, "fetch", "--all", "--prune"); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := runAsUser(ctx, spec.RunAsUser, &output, "git", "-C", spec.TargetDirectory, "checkout", spec.Branch); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
		if err := runAsUser(ctx, spec.RunAsUser, &output, "git", "-C", spec.TargetDirectory, "pull", "--ff-only", "origin", spec.Branch); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
	} else {
		if err := runAsUser(ctx, spec.RunAsUser, &output, "git", "clone", "--branch", spec.Branch, spec.RepositoryURL, spec.TargetDirectory); err != nil {
			return DeployResult{Action: action, Output: output.String()}, err
		}
	}

	commitSHA, err := currentCommit(ctx, spec.RunAsUser, spec.TargetDirectory, &output)
	if err != nil {
		return DeployResult{Action: action, Output: output.String(), PreviousCommitSHA: previousCommit}, err
	}

	if strings.TrimSpace(spec.PostDeployCommand) != "" {
		action = action + " + post-deploy"
		if err := runShellAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, spec.PostDeployCommand, &output); err != nil {
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
		if err := runShellAsUser(ctx, spec.RunAsUser, spec.TargetDirectory, spec.PostDeployCommand, &output); err != nil {
			return DeployResult{Action: "rollback + post-deploy", Output: output.String(), PreviousCommitSHA: previousCommit, CommitSHA: spec.ReleaseCommitSHA}, err
		}
	}
	commitSHA, err := currentCommit(ctx, spec.RunAsUser, spec.TargetDirectory, &output)
	if err != nil {
		return DeployResult{Action: "rollback", Output: output.String(), PreviousCommitSHA: previousCommit}, err
	}
	return DeployResult{Action: "rollback", Output: strings.TrimSpace(output.String()), CommitSHA: commitSHA, PreviousCommitSHA: previousCommit}, nil
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

func runAsUser(ctx context.Context, username string, output *bytes.Buffer, name string, args ...string) error {
	fullArgs := append([]string{"-u", username, "--", name}, args...)
	cmd := exec.CommandContext(ctx, "sudo", fullArgs...)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

func runShellAsUser(ctx context.Context, username string, workingDir string, command string, output *bytes.Buffer) error {
	shellCommand := fmt.Sprintf("cd %s && %s", shellQuote(workingDir), command)
	cmd := exec.CommandContext(ctx, "sudo", "-u", username, "--", "sh", "-lc", shellCommand)
	cmd.Stdout = output
	cmd.Stderr = output
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
