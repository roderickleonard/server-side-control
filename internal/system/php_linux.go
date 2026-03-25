//go:build linux

package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var fastCGIPassPattern = regexp.MustCompile(`fastcgi_pass\s+unix:/run/php/php[0-9.]+-fpm\.sock;`)

type linuxPHPManager struct{}

func NewPHPManager() PHPManager {
	return linuxPHPManager{}
}

func (linuxPHPManager) ListAvailableVersions() ([]string, error) {
	versionSet := map[string]struct{}{}

	entries, err := os.ReadDir("/etc/php")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !phpVersionPattern.MatchString(entry.Name()) {
				continue
			}
			if _, statErr := os.Stat(filepath.Join("/etc/php", entry.Name(), "fpm")); statErr == nil {
				versionSet[entry.Name()] = struct{}{}
			}
		}
	}

	sockets, globErr := filepath.Glob("/run/php/php*-fpm.sock")
	if globErr == nil {
		for _, socketPath := range sockets {
			name := strings.TrimSuffix(filepath.Base(socketPath), "-fpm.sock")
			name = strings.TrimPrefix(name, "php")
			if phpVersionPattern.MatchString(name) {
				versionSet[name] = struct{}{}
			}
		}
	}

	versions := make([]string, 0, len(versionSet))
	for version := range versionSet {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	return versions, nil
}

func (linuxPHPManager) SwitchSiteVersion(configPath string, version string) error {
	configPath = strings.TrimSpace(configPath)
	version = strings.TrimSpace(version)
	if !filepath.IsAbs(configPath) {
		return ErrInvalidRootDirectory
	}
	if !phpVersionPattern.MatchString(version) {
		return ErrInvalidPHPVersion
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	updated := fastCGIPassPattern.ReplaceAllString(string(content), fmt.Sprintf("fastcgi_pass unix:/run/php/php%s-fpm.sock;", version))
	if updated == string(content) {
		return fmt.Errorf("no php-fpm socket declaration found in nginx config")
	}

	if err := os.WriteFile(configPath, []byte(updated), 0o644); err != nil {
		return err
	}
	if err := exec.Command("nginx", "-t").Run(); err != nil {
		_ = os.WriteFile(configPath, content, 0o644)
		return fmt.Errorf("nginx config validation failed: %w", err)
	}
	if output, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		_ = os.WriteFile(configPath, content, 0o644)
		return fmt.Errorf("nginx reload failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
