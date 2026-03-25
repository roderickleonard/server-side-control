//go:build linux

package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var fastCGIPassPattern = regexp.MustCompile(`fastcgi_pass\s+unix:/run/php/php[0-9.]+-fpm\.sock;`)

type linuxPHPManager struct{}

func NewPHPManager() PHPManager {
	return linuxPHPManager{}
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
