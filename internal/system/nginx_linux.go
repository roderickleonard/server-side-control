//go:build linux

package system

import (
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

var siteNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
var domainPattern = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
var upstreamPattern = regexp.MustCompile(`^(https?://)?[a-zA-Z0-9._:-]+$`)
var phpVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

var ErrInvalidSiteName = errors.New("invalid site name")
var ErrInvalidDomain = errors.New("invalid domain")
var ErrInvalidMode = errors.New("invalid site mode")
var ErrInvalidUpstream = errors.New("invalid reverse proxy upstream")
var ErrInvalidRootDirectory = errors.New("invalid root directory")
var ErrInvalidPHPVersion = errors.New("invalid php version")
var ErrInvalidEmail = errors.New("invalid email")

type SiteSpec struct {
	Name          string
	OwnerLinuxUser string
	Domain        string
	Mode          string
	RootDirectory string
	UpstreamURL   string
	PHPVersion    string
}

type TLSRequest struct {
	Domain   string
	Email    string
	Redirect bool
}

type linuxNginxManager struct {
	availableDir string
	enabledDir   string
	binary       string
	certbot      string
}

var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func NewNginxManager(availableDir string, enabledDir string, binary string, certbot string) NginxManager {
	if availableDir == "" {
		availableDir = "/etc/nginx/sites-available"
	}
	if enabledDir == "" {
		enabledDir = "/etc/nginx/sites-enabled"
	}
	if binary == "" {
		binary = "nginx"
	}
	if certbot == "" {
		certbot = "certbot"
	}
	return linuxNginxManager{availableDir: availableDir, enabledDir: enabledDir, binary: binary, certbot: certbot}
}

func (m linuxNginxManager) ApplySite(spec SiteSpec) (string, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	spec.OwnerLinuxUser = strings.TrimSpace(spec.OwnerLinuxUser)
	spec.Domain = strings.TrimSpace(spec.Domain)
	spec.Mode = strings.TrimSpace(spec.Mode)
	spec.RootDirectory = strings.TrimSpace(spec.RootDirectory)
	spec.UpstreamURL = strings.TrimSpace(spec.UpstreamURL)
	spec.PHPVersion = strings.TrimSpace(spec.PHPVersion)

	switch spec.Mode {
	case "reverse_proxy":
		spec.RootDirectory = ""
		spec.PHPVersion = ""
	case "static":
		spec.UpstreamURL = ""
		spec.PHPVersion = ""
	case "php":
		spec.UpstreamURL = ""
	}

	if !siteNamePattern.MatchString(spec.Name) {
		return "", ErrInvalidSiteName
	}
	if spec.OwnerLinuxUser != "" && !usernamePattern.MatchString(spec.OwnerLinuxUser) {
		return "", ErrInvalidUsername
	}
	if !domainPattern.MatchString(spec.Domain) {
		return "", ErrInvalidDomain
	}
	if spec.Mode != "reverse_proxy" && spec.Mode != "static" && spec.Mode != "php" {
		return "", ErrInvalidMode
	}
	if spec.Mode == "reverse_proxy" && !upstreamPattern.MatchString(spec.UpstreamURL) {
		return "", ErrInvalidUpstream
	}
	if (spec.Mode == "static" || spec.Mode == "php") && !filepath.IsAbs(spec.RootDirectory) {
		return "", ErrInvalidRootDirectory
	}
	if spec.Mode == "php" && !phpVersionPattern.MatchString(spec.PHPVersion) {
		return "", ErrInvalidPHPVersion
	}
	if spec.Mode == "static" || spec.Mode == "php" {
		if err := ensureSiteRootDirectory(spec.RootDirectory, spec.OwnerLinuxUser); err != nil {
			return "", err
		}
	}

	if err := os.MkdirAll(m.availableDir, 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(m.enabledDir, 0o755); err != nil {
		return "", err
	}

	configPath := filepath.Join(m.availableDir, spec.Name+".conf")
	enabledPath := filepath.Join(m.enabledDir, spec.Name+".conf")
	configBody := renderNginxConfig(spec)

	previousConfig, hadPreviousConfig := readIfExists(configPath)
	hadPreviousLink := fileExists(enabledPath)

	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		return "", err
	}
	if !hadPreviousLink {
		if err := os.Symlink(configPath, enabledPath); err != nil && !os.IsExist(err) {
			rollbackSite(configPath, enabledPath, hadPreviousConfig, previousConfig, hadPreviousLink)
			return "", err
		}
	}

	if err := m.ValidateConfig(configPath); err != nil {
		rollbackSite(configPath, enabledPath, hadPreviousConfig, previousConfig, hadPreviousLink)
		return "", err
	}
	if err := m.Reload(); err != nil {
		rollbackSite(configPath, enabledPath, hadPreviousConfig, previousConfig, hadPreviousLink)
		return "", err
	}

	return configPath, nil
}

func ensureSiteRootDirectory(rootDirectory string, ownerLinuxUser string) error {
	if err := os.MkdirAll(rootDirectory, 0o755); err != nil {
		return fmt.Errorf("create site root directory: %w", err)
	}
	if ownerLinuxUser == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "id", "-u", ownerLinuxUser).Run(); err != nil {
		return ErrUserNotFound
	}

	cmd := exec.CommandContext(ctx, "chown", "-R", ownerLinuxUser+":"+ownerLinuxUser, rootDirectory)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chown site root directory: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m linuxNginxManager) ValidateConfig(_ string) error {
	cmd := exec.Command(m.binary, "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m linuxNginxManager) Reload() error {
	cmd := exec.Command("systemctl", "reload", "nginx")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx reload failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m linuxNginxManager) EnableTLS(request TLSRequest) (string, error) {
	request.Domain = strings.TrimSpace(request.Domain)
	request.Email = strings.TrimSpace(request.Email)
	if !domainPattern.MatchString(request.Domain) {
		return "", ErrInvalidDomain
	}
	if !emailPattern.MatchString(request.Email) {
		return "", ErrInvalidEmail
	}

	args := []string{"--nginx", "-d", request.Domain, "-m", request.Email, "--agree-tos", "--non-interactive"}
	if request.Redirect {
		args = append(args, "--redirect")
	}
	cmd := exec.Command(m.certbot, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("certbot failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := m.ValidateConfig(""); err != nil {
		return "", err
	}
	if err := m.Reload(); err != nil {
		return "", err
	}
	return renderTLSServerBlock(request.Domain), nil
}

func renderNginxConfig(spec SiteSpec) string {
	switch spec.Mode {
	case "reverse_proxy":
		upstream := spec.UpstreamURL
		if !strings.HasPrefix(upstream, "http://") && !strings.HasPrefix(upstream, "https://") {
			upstream = "http://" + upstream
		}
		return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;

    location / {
        proxy_pass %s;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`, spec.Domain, upstream)
	case "php":
		return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    root %s;
    index index.php index.html index.htm;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php%s-fpm.sock;
    }
}
`, spec.Domain, spec.RootDirectory, spec.PHPVersion)
	default:
		return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    root %s;
    index index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }
}
`, spec.Domain, spec.RootDirectory)
	}
}

func rollbackSite(configPath string, enabledPath string, hadPreviousConfig bool, previousConfig []byte, hadPreviousLink bool) {
	if hadPreviousConfig {
		_ = os.WriteFile(configPath, previousConfig, 0o644)
	} else {
		_ = os.Remove(configPath)
	}
	if !hadPreviousLink {
		_ = os.Remove(enabledPath)
	}
}

func readIfExists(path string) ([]byte, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return content, true
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func renderTLSServerBlock(domain string) string {
	return fmt.Sprintf(`ssl_certificate /etc/letsencrypt/live/%s/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/%s/privkey.pem;`, domain, domain)
}
