package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	AppName           string
	Environment       string
	EnvPath           string
	ListenAddr        string
	BaseURL           string
	DatabaseDSN       string
	BootstrapUser     string
	BootstrapPassword string
	PAMService        string
	SessionCookieName string
	ServiceName string
	SMTPHost          string
	SMTPPort          string
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	SMTPTo            string
	MySQLAdminDefaultsFile string
	DatabaseRestoreMaxBytes int64
	NginxBinary       string
	NginxAvailableDir string
	NginxEnabledDir   string
	SubdomainRootBaseDir string
	CertbotBinary     string
	HelperBinary      string
}

func Load() (Config, error) {
	envPath := resolveEnvPath()

	_ = loadEnvFile(envPath)

	cfg := Config{
		AppName:           getenv("PANEL_APP_NAME", "Server Side Control"),
		Environment:       getenv("PANEL_ENV", "development"),
		EnvPath:           envPath,
		ListenAddr:        getenv("PANEL_LISTEN_ADDR", ":8080"),
		BaseURL:           getenv("PANEL_BASE_URL", "http://127.0.0.1:8080"),
		DatabaseDSN:       os.Getenv("PANEL_DATABASE_DSN"),
		BootstrapUser:     getenv("PANEL_BOOTSTRAP_USER", "admin"),
		BootstrapPassword: os.Getenv("PANEL_BOOTSTRAP_PASSWORD"),
		PAMService:        getenv("PANEL_PAM_SERVICE", "login"),
		SessionCookieName: getenv("PANEL_SESSION_COOKIE_NAME", "ssc_session"),
		ServiceName:       getenv("PANEL_SERVICE_NAME", "server-side-control"),
		SMTPHost:          getenv("PANEL_SMTP_HOST", ""),
		SMTPPort:          getenv("PANEL_SMTP_PORT", "587"),
		SMTPUsername:      getenv("PANEL_SMTP_USERNAME", ""),
		SMTPPassword:      os.Getenv("PANEL_SMTP_PASSWORD"),
		SMTPFrom:          getenv("PANEL_SMTP_FROM", ""),
		SMTPTo:            getenv("PANEL_SMTP_TO", ""),
		MySQLAdminDefaultsFile: getenv("PANEL_MYSQL_ADMIN_DEFAULTS_FILE", "/etc/server-side-control/mysql-admin.cnf"),
		DatabaseRestoreMaxBytes: getenvInt64Bytes("PANEL_DATABASE_RESTORE_MAX_MB", 64) * (1 << 20),
		NginxBinary:       getenv("PANEL_NGINX_BINARY", "nginx"),
		NginxAvailableDir: getenv("PANEL_NGINX_AVAILABLE_DIR", "/etc/nginx/sites-available"),
		NginxEnabledDir:   getenv("PANEL_NGINX_ENABLED_DIR", "/etc/nginx/sites-enabled"),
		SubdomainRootBaseDir: getenv("PANEL_SUBDOMAIN_ROOT_BASE", ""),
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
		fmt.Sprintf("PANEL_SERVICE_NAME=%s", c.ServiceName),
		fmt.Sprintf("PANEL_SMTP_HOST=%s", c.SMTPHost),
		fmt.Sprintf("PANEL_SMTP_PORT=%s", c.SMTPPort),
		fmt.Sprintf("PANEL_SMTP_USERNAME=%s", c.SMTPUsername),
		fmt.Sprintf("PANEL_SMTP_PASSWORD=%s", c.SMTPPassword),
		fmt.Sprintf("PANEL_SMTP_FROM=%s", c.SMTPFrom),
		fmt.Sprintf("PANEL_SMTP_TO=%s", c.SMTPTo),
		fmt.Sprintf("PANEL_MYSQL_ADMIN_DEFAULTS_FILE=%s", c.MySQLAdminDefaultsFile),
		fmt.Sprintf("PANEL_DATABASE_RESTORE_MAX_MB=%d", c.DatabaseRestoreMaxBytes/(1<<20)),
		fmt.Sprintf("PANEL_NGINX_BINARY=%s", c.NginxBinary),
		fmt.Sprintf("PANEL_NGINX_AVAILABLE_DIR=%s", c.NginxAvailableDir),
		fmt.Sprintf("PANEL_NGINX_ENABLED_DIR=%s", c.NginxEnabledDir),
		fmt.Sprintf("PANEL_SUBDOMAIN_ROOT_BASE=%s", c.SubdomainRootBaseDir),
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

func getenvInt64Bytes(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
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
