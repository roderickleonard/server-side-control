package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	AppName           string
	Environment       string
	ListenAddr        string
	BaseURL           string
	DatabaseDSN       string
	BootstrapUser     string
	BootstrapPassword string
	PAMService        string
	SessionCookieName string
	MySQLAdminDefaultsFile string
	NginxBinary       string
	NginxAvailableDir string
	NginxEnabledDir   string
	CertbotBinary     string
	HelperBinary      string
}

func Load() (Config, error) {
	envPath := resolveEnvPath()

	_ = loadEnvFile(envPath)

	cfg := Config{
		AppName:           getenv("PANEL_APP_NAME", "Server Side Control"),
		Environment:       getenv("PANEL_ENV", "development"),
		ListenAddr:        getenv("PANEL_LISTEN_ADDR", ":8080"),
		BaseURL:           getenv("PANEL_BASE_URL", "http://127.0.0.1:8080"),
		DatabaseDSN:       os.Getenv("PANEL_DATABASE_DSN"),
		BootstrapUser:     getenv("PANEL_BOOTSTRAP_USER", "admin"),
		BootstrapPassword: os.Getenv("PANEL_BOOTSTRAP_PASSWORD"),
		PAMService:        getenv("PANEL_PAM_SERVICE", "login"),
		SessionCookieName: getenv("PANEL_SESSION_COOKIE_NAME", "ssc_session"),
		MySQLAdminDefaultsFile: getenv("PANEL_MYSQL_ADMIN_DEFAULTS_FILE", "/etc/server-side-control/mysql-admin.cnf"),
		NginxBinary:       getenv("PANEL_NGINX_BINARY", "nginx"),
		NginxAvailableDir: getenv("PANEL_NGINX_AVAILABLE_DIR", "/etc/nginx/sites-available"),
		NginxEnabledDir:   getenv("PANEL_NGINX_ENABLED_DIR", "/etc/nginx/sites-enabled"),
		CertbotBinary:     getenv("PANEL_CERTBOT_BINARY", "certbot"),
		HelperBinary:      getenv("PANEL_HELPER_BINARY", "/usr/local/bin/server-side-control-helper"),
	}

	return cfg, nil
}

func resolveEnvPath() string {
	if envPath := os.Getenv("PANEL_ENV_FILE"); envPath != "" {
		return envPath
	}

	const localEnvPath = "config/panel.env"
	if _, err := os.Stat(localEnvPath); err == nil {
		return localEnvPath
	}

	return "/etc/server-side-control/panel.env"
}

func (c Config) ToEnv() string {
	return strings.Join([]string{
		fmt.Sprintf("PANEL_APP_NAME=%s", c.AppName),
		fmt.Sprintf("PANEL_ENV=%s", c.Environment),
		fmt.Sprintf("PANEL_LISTEN_ADDR=%s", c.ListenAddr),
		fmt.Sprintf("PANEL_BASE_URL=%s", c.BaseURL),
		fmt.Sprintf("PANEL_DATABASE_DSN=%s", c.DatabaseDSN),
		fmt.Sprintf("PANEL_BOOTSTRAP_USER=%s", c.BootstrapUser),
		fmt.Sprintf("PANEL_BOOTSTRAP_PASSWORD=%s", c.BootstrapPassword),
		fmt.Sprintf("PANEL_PAM_SERVICE=%s", c.PAMService),
		fmt.Sprintf("PANEL_SESSION_COOKIE_NAME=%s", c.SessionCookieName),
		fmt.Sprintf("PANEL_MYSQL_ADMIN_DEFAULTS_FILE=%s", c.MySQLAdminDefaultsFile),
		fmt.Sprintf("PANEL_NGINX_BINARY=%s", c.NginxBinary),
		fmt.Sprintf("PANEL_NGINX_AVAILABLE_DIR=%s", c.NginxAvailableDir),
		fmt.Sprintf("PANEL_NGINX_ENABLED_DIR=%s", c.NginxEnabledDir),
		fmt.Sprintf("PANEL_CERTBOT_BINARY=%s", c.CertbotBinary),
		fmt.Sprintf("PANEL_HELPER_BINARY=%s", c.HelperBinary),
	}, "\n") + "\n"
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}

	return scanner.Err()
}
