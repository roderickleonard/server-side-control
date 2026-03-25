//go:build linux

package system

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var gitHostPattern = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
var credentialUsernamePattern = regexp.MustCompile(`^[^\s:@/]+$`)

type linuxGitAuthManager struct{}

func NewGitAuthManager() GitAuthManager {
	return linuxGitAuthManager{}
}

func (linuxGitAuthManager) Inspect(spec GitAuthInspectSpec) (GitAuthStatus, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return GitAuthStatus{}, err
	}
	protocol, host := parseRepositoryEndpoint(spec.RepositoryURL)
	status := GitAuthStatus{
		User:                strings.TrimSpace(spec.User),
		HomeDirectory:       homeDirectory,
		RepositoryProtocol:  protocol,
		RepositoryHost:      host,
		SSHKeyPath:          deployKeyBasePath(homeDirectory, spec.SiteName),
		CredentialStorePath: filepath.Join(homeDirectory, ".git-credentials"),
	}
	publicKeyPath := status.SSHKeyPath + ".pub"
	if content, err := os.ReadFile(publicKeyPath); err == nil {
		status.PublicKey = strings.TrimSpace(string(content))
		status.DeployKeyReady = status.PublicKey != ""
	}
	if host != "" {
		status.KnownHostTrusted = knownHostTrusted(filepath.Join(homeDirectory, ".ssh", "known_hosts"), host)
	}
	status.CredentialConfigured = credentialConfigured(status.CredentialStorePath, protocol, host)
	return status, nil
}

func (m linuxGitAuthManager) EnsureDeployKey(spec GitDeployKeySpec) (GitAuthStatus, string, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return GitAuthStatus{}, "", err
	}
	basePath := deployKeyBasePath(homeDirectory, spec.SiteName)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	script := fmt.Sprintf("set -e; mkdir -p %s; chmod 700 %s; if [ ! -f %s ]; then ssh-keygen -t ed25519 -N '' -C %s -f %s; else echo 'Deploy key already exists'; fi; cat %s",
		shellQuote(filepath.Join(homeDirectory, ".ssh")),
		shellQuote(filepath.Join(homeDirectory, ".ssh")),
		shellQuote(basePath),
		shellQuote(spec.SiteName+" deploy key"),
		shellQuote(basePath),
		shellQuote(basePath+".pub"),
	)
	output, err := runBashAsUser(ctx, spec.User, script)
	status, inspectErr := m.Inspect(GitAuthInspectSpec{User: spec.User, SiteName: spec.SiteName, RepositoryURL: spec.RepositoryURL})
	if err != nil {
		return status, output, err
	}
	if inspectErr != nil {
		return status, output, inspectErr
	}
	return status, output, nil
}

func (linuxGitAuthManager) TrustHost(spec GitHostTrustSpec) (string, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(spec.Host)
	if !gitHostPattern.MatchString(host) {
		return "", ErrInvalidGitHost
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	knownHostsPath := filepath.Join(homeDirectory, ".ssh", "known_hosts")
	script := fmt.Sprintf("set -e; mkdir -p %s; chmod 700 %s; touch %s; chmod 600 %s; if ssh-keygen -F %s -f %s >/dev/null 2>&1; then echo 'Host already trusted'; else ssh-keyscan -H %s >> %s; echo 'Host added to known_hosts'; fi",
		shellQuote(filepath.Join(homeDirectory, ".ssh")),
		shellQuote(filepath.Join(homeDirectory, ".ssh")),
		shellQuote(knownHostsPath),
		shellQuote(knownHostsPath),
		shellQuote(host),
		shellQuote(knownHostsPath),
		shellQuote(host),
		shellQuote(knownHostsPath),
	)
	return runBashAsUser(ctx, spec.User, script)
}

func (linuxGitAuthManager) StoreCredential(spec GitCredentialSpec) (string, error) {
	homeDirectory, err := lookupUserHome(spec.User)
	if err != nil {
		return "", err
	}
	protocol := strings.TrimSpace(strings.ToLower(spec.Protocol))
	if protocol != "https" && protocol != "http" {
		return "", ErrInvalidCredentialProtocol
	}
	host := strings.TrimSpace(spec.Host)
	if !gitHostPattern.MatchString(host) {
		return "", ErrInvalidGitHost
	}
	username := strings.TrimSpace(spec.Username)
	if !credentialUsernamePattern.MatchString(username) {
		return "", ErrInvalidCredentialUsername
	}
	if strings.TrimSpace(spec.Password) == "" {
		return "", ErrInvalidCredentialPassword
	}
	credentialURL := (&url.URL{Scheme: protocol, Host: host, User: url.UserPassword(username, spec.Password)}).String()
	credentialsPath := filepath.Join(homeDirectory, ".git-credentials")
	entries := make([]string, 0)
	if content, err := os.ReadFile(credentialsPath); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parsed, parseErr := url.Parse(line)
			if parseErr == nil && strings.EqualFold(parsed.Scheme, protocol) && strings.EqualFold(parsed.Hostname(), host) {
				continue
			}
			entries = append(entries, line)
		}
	}
	entries = append(entries, credentialURL)
	content := strings.Join(entries, "\n") + "\n"
	if err := os.WriteFile(credentialsPath, []byte(content), 0o600); err != nil {
		return "", err
	}
	uid, gid, err := lookupUserIDs(spec.User)
	if err == nil {
		_ = os.Chown(credentialsPath, uid, gid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := runBashAsUser(ctx, spec.User, "git config --global credential.helper store"); err != nil {
		return "", err
	}
	return "Credentials stored for " + protocol + "://" + host, nil
}

func parseRepositoryEndpoint(repositoryURL string) (string, string) {
	repositoryURL = strings.TrimSpace(repositoryURL)
	if repositoryURL == "" {
		return "", ""
	}
	if strings.Contains(repositoryURL, "://") {
		parsed, err := url.Parse(repositoryURL)
		if err == nil {
			return strings.ToLower(parsed.Scheme), parsed.Hostname()
		}
	}
	if at := strings.Index(repositoryURL, "@"); at >= 0 {
		remainder := repositoryURL[at+1:]
		if colon := strings.Index(remainder, ":"); colon >= 0 {
			return "ssh", remainder[:colon]
		}
	}
	return "", ""
}

func deployKeyBasePath(homeDirectory string, siteName string) string {
	cleanName := strings.ToLower(strings.TrimSpace(siteName))
	if cleanName == "" {
		cleanName = "site"
	}
	replacer := strings.NewReplacer("/", "-", " ", "-", "_", "-")
	cleanName = replacer.Replace(cleanName)
	return filepath.Join(homeDirectory, ".ssh", "server-side-control-"+cleanName+"-deploy")
}

func knownHostTrusted(path string, host string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, host+" ") || strings.HasPrefix(line, "|1|") || strings.Contains(line, " "+host+" ") || strings.HasPrefix(line, "["+host+"]:") {
			if strings.Contains(line, host) || strings.HasPrefix(line, "|1|") {
				return true
			}
		}
	}
	return false
}

func credentialConfigured(path string, protocol string, host string) bool {
	if protocol == "" || host == "" {
		return false
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil {
			continue
		}
		if strings.EqualFold(parsed.Scheme, protocol) && strings.EqualFold(parsed.Hostname(), host) {
			return true
		}
	}
	return false
}