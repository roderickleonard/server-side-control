package system

import (
	"testing"
)

func TestValidateGitCommand(t *testing.T) {
	validCases := []struct {
		name    string
		command string
	}{
		{"git status", "git status"},
		{"git pull origin main", "git pull origin main"},
		{"git checkout feature branch with slash", "git checkout feature/my-branch"},
		{"git remote add origin https URL", "git remote add origin https://github.com/user/repo.git"},
		{"git log with flags", "git log --oneline --graph"},
		{"git fetch all", "git fetch --all"},
		{"git commit with message flag", "git commit -m message"},
		{"git with trailing whitespace", "  git status  "},
		{"git push with remote and branch", "git push origin main"},
		{"git tag", "git tag v1.0.0"},
		{"git stash", "git stash"},
		{"git diff with flag", "git diff --stat"},
		{"git branch list", "git branch -a"},
		{"git rebase", "git rebase origin/main"},
		{"git clone with URL", "git clone https://github.com/user/repo.git"},
		{"git with colon in arg", "git fetch origin refs/heads/main:refs/remotes/origin/main"},
		{"git with equals sign", "git config user.email=user@example.com"},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateGitCommand(tc.command); err != nil {
				t.Errorf("expected no error for %q, got %v", tc.command, err)
			}
		})
	}

	invalidCases := []struct {
		name    string
		command string
	}{
		{"empty command", ""},
		{"whitespace only", "   "},
		{"newline in command", "git status\ngit pull"},
		{"carriage return in command", "git status\rgit pull"},
		{"not starting with git", "ls -la"},
		{"gitsomething without space", "gitsomething"},
		{"gitcommit without space", "gitcommit"},
		{"pipe character", "git status | grep modified"},
		{"semicolon", "git status; ls"},
		{"backtick", "git status `whoami`"},
		{"dollar sign", "git status $HOME"},
		{"open parenthesis", "git status (test)"},
		{"close parenthesis", "git log)"},
		{"open brace", "git status {foo}"},
		{"close brace", "git status }"},
		{"open bracket", "git status [HEAD]"},
		{"close bracket", "git status ]"},
		{"backslash", "git status \\n"},
		{"double quote", `git commit -m "message"`},
		{"ampersand", "git status && git pull"},
		{"less-than", "git log < file"},
		{"greater-than", "git log > file"},
		// "git commit -m my message" is actually valid — "my" and "message" are
		// separate tokens, each containing only letters, which are allowed.
		// Use a genuinely invalid arg: one containing a percent sign (not in allowlist).
		{"argument with percent sign", "git log --format=%H"},
		{"completely unrelated command", "rm -rf /"},
		{"sudo prefix", "sudo git status"},
		{"shell injection via subcommand", "git $(ls)"},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGitCommand(tc.command)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc.command)
			}
			if err != ErrInvalidGitCommand {
				t.Errorf("expected ErrInvalidGitCommand for %q, got %v", tc.command, err)
			}
		})
	}
}

func TestValidateGitCommandAllowedSpecialChars(t *testing.T) {
	// These characters in arguments should be allowed
	allowedArgCases := []struct {
		name    string
		command string
	}{
		{"dot in arg", "git checkout v1.2.3"},
		{"underscore in arg", "git checkout my_branch"},
		{"slash in arg", "git checkout origin/main"},
		{"colon in arg", "git fetch origin main:local"},
		{"equals in arg", "git config --global core.autocrlf=false"},
		{"at sign in arg", "git config user.email=user@example.com"},
		{"comma in arg", "git config core.editor=nano"},
		{"plus in arg", "git log --oneline"},
		{"dash in arg", "git log --oneline"},
	}

	for _, tc := range allowedArgCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateGitCommand(tc.command); err != nil {
				t.Errorf("expected no error for %q, got %v", tc.command, err)
			}
		})
	}
}
