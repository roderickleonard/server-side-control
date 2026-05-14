package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// getenv
// ---------------------------------------------------------------------------

func TestGetenv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		setValue string
		setEnv   bool
		fallback string
		want     string
	}{
		{
			name:     "env not set returns fallback",
			key:      "TEST_GETENV_NOTSET",
			setEnv:   false,
			fallback: "default_value",
			want:     "default_value",
		},
		{
			name:     "env set returns value",
			key:      "TEST_GETENV_SET",
			setValue: "actual_value",
			setEnv:   true,
			fallback: "default_value",
			want:     "actual_value",
		},
		{
			name:     "empty env value returns fallback",
			key:      "TEST_GETENV_EMPTY",
			setValue: "",
			setEnv:   true,
			fallback: "fallback_for_empty",
			want:     "fallback_for_empty",
		},
		{
			name:     "fallback is empty string and env not set",
			key:      "TEST_GETENV_EMPTY_FALLBACK",
			setEnv:   false,
			fallback: "",
			want:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv(tc.key, tc.setValue)
			}
			got := getenv(tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("getenv(%q, %q) = %q; want %q", tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getenvInt64Bytes
// ---------------------------------------------------------------------------

func TestGetenvInt64Bytes(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		setValue string
		setEnv   bool
		fallback int64
		want     int64
	}{
		{
			name:     "not set returns fallback",
			key:      "TEST_INT64_NOTSET",
			setEnv:   false,
			fallback: 64,
			want:     64,
		},
		{
			name:     "set to 128 returns 128",
			key:      "TEST_INT64_128",
			setValue: "128",
			setEnv:   true,
			fallback: 64,
			want:     128,
		},
		{
			name:     "set to 0 returns fallback (zero treated as invalid)",
			key:      "TEST_INT64_ZERO",
			setValue: "0",
			setEnv:   true,
			fallback: 64,
			want:     64,
		},
		{
			name:     "set to negative returns fallback",
			key:      "TEST_INT64_NEG",
			setValue: "-10",
			setEnv:   true,
			fallback: 64,
			want:     64,
		},
		{
			name:     "set to non-numeric returns fallback",
			key:      "TEST_INT64_NAN",
			setValue: "abc",
			setEnv:   true,
			fallback: 64,
			want:     64,
		},
		{
			name:     "set with surrounding whitespace parses correctly",
			key:      "TEST_INT64_TRIM",
			setValue: "  256  ",
			setEnv:   true,
			fallback: 64,
			want:     256,
		},
		{
			name:     "empty string returns fallback",
			key:      "TEST_INT64_EMPTYSTR",
			setValue: "",
			setEnv:   true,
			fallback: 32,
			want:     32,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv(tc.key, tc.setValue)
			}
			got := getenvInt64Bytes(tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("getenvInt64Bytes(%q, %d) = %d; want %d", tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// loadEnvFile
// ---------------------------------------------------------------------------

func TestLoadEnvFile(t *testing.T) {
	t.Run("non-existent file returns error", func(t *testing.T) {
		err := loadEnvFile("/tmp/does_not_exist_panel_test_abc123.env")
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
	})

	t.Run("valid file sets env vars", func(t *testing.T) {
		dir := t.TempDir()
		envFile := filepath.Join(dir, "panel.env")

		content := "# This is a comment\n\nTEST_LOAD_KEY1=hello\nTEST_LOAD_KEY2=world\n"
		if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write temp env file: %v", err)
		}

		// Pre-clean the keys so we can verify they are set by loadEnvFile.
		t.Setenv("TEST_LOAD_KEY1", "")
		t.Setenv("TEST_LOAD_KEY2", "")

		if err := loadEnvFile(envFile); err != nil {
			t.Fatalf("loadEnvFile returned unexpected error: %v", err)
		}

		if got := os.Getenv("TEST_LOAD_KEY1"); got != "hello" {
			t.Errorf("TEST_LOAD_KEY1 = %q; want %q", got, "hello")
		}
		if got := os.Getenv("TEST_LOAD_KEY2"); got != "world" {
			t.Errorf("TEST_LOAD_KEY2 = %q; want %q", got, "world")
		}
	})

	t.Run("comments and blank lines are ignored", func(t *testing.T) {
		dir := t.TempDir()
		envFile := filepath.Join(dir, "panel.env")

		content := "# comment line\n\n   # another comment\n\nTEST_LOAD_COMMENT_KEY=value\n"
		if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write temp env file: %v", err)
		}

		t.Setenv("TEST_LOAD_COMMENT_KEY", "")

		if err := loadEnvFile(envFile); err != nil {
			t.Fatalf("loadEnvFile returned unexpected error: %v", err)
		}

		if got := os.Getenv("TEST_LOAD_COMMENT_KEY"); got != "value" {
			t.Errorf("TEST_LOAD_COMMENT_KEY = %q; want %q", got, "value")
		}
	})

	t.Run("value with equals sign is preserved", func(t *testing.T) {
		dir := t.TempDir()
		envFile := filepath.Join(dir, "panel.env")

		// SplitN with n=2 means only the first '=' is split on.
		content := "TEST_LOAD_EQ_KEY=a=b=c\n"
		if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write temp env file: %v", err)
		}

		t.Setenv("TEST_LOAD_EQ_KEY", "")

		if err := loadEnvFile(envFile); err != nil {
			t.Fatalf("loadEnvFile returned unexpected error: %v", err)
		}

		if got := os.Getenv("TEST_LOAD_EQ_KEY"); got != "a=b=c" {
			t.Errorf("TEST_LOAD_EQ_KEY = %q; want %q", got, "a=b=c")
		}
	})

	t.Run("line without equals sign is skipped", func(t *testing.T) {
		dir := t.TempDir()
		envFile := filepath.Join(dir, "panel.env")

		content := "NOEQUALS\nTEST_LOAD_SKIP_KEY=kept\n"
		if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write temp env file: %v", err)
		}

		t.Setenv("TEST_LOAD_SKIP_KEY", "")

		if err := loadEnvFile(envFile); err != nil {
			t.Fatalf("loadEnvFile returned unexpected error: %v", err)
		}

		if got := os.Getenv("TEST_LOAD_SKIP_KEY"); got != "kept" {
			t.Errorf("TEST_LOAD_SKIP_KEY = %q; want %q", got, "kept")
		}
	})
}

// ---------------------------------------------------------------------------
// Config.ToEnv
// ---------------------------------------------------------------------------

func TestConfigToEnv(t *testing.T) {
	t.Run("output contains expected keys", func(t *testing.T) {
		cfg := Config{
			AppName:                "TestPanel",
			Environment:            "production",
			ListenAddr:             ":9090",
			BaseURL:                "https://panel.example.com",
			DatabaseDSN:            "user:pass@tcp(localhost:3306)/db",
			BootstrapUser:          "admin",
			BootstrapPassword:      "secret",
			PAMService:             "login",
			SessionCookieName:      "ssc_session",
			ServiceName:            "server-side-control",
			SMTPHost:               "smtp.example.com",
			SMTPPort:               "587",
			SMTPUsername:           "user@example.com",
			SMTPPassword:           "smtppass",
			SMTPFrom:               "noreply@example.com",
			SMTPTo:                 "admin@example.com",
			OpenAIAPIKey:           "sk-testkey",
			OpenAIModel:            "gpt-4.1-mini",
			MySQLAdminDefaultsFile: "/etc/server-side-control/mysql-admin.cnf",
			DatabaseRestoreMaxBytes: 64 * (1 << 20),
			NginxBinary:            "nginx",
			NginxAvailableDir:      "/etc/nginx/sites-available",
			NginxEnabledDir:        "/etc/nginx/sites-enabled",
			SubdomainRootBaseDir:   "/var/www",
			CertbotBinary:          "certbot",
			HelperBinary:           "/usr/local/bin/server-side-control-helper",
			AWSAccessKeyID:         "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey:     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		}

		output := cfg.ToEnv()

		expectedKeys := []string{
			"PANEL_APP_NAME=",
			"PANEL_ENV=",
			"PANEL_LISTEN_ADDR=",
			"PANEL_BASE_URL=",
			"PANEL_DATABASE_DSN=",
			"PANEL_BOOTSTRAP_USER=",
			"PANEL_BOOTSTRAP_PASSWORD=",
			"PANEL_PAM_SERVICE=",
			"PANEL_SESSION_COOKIE_NAME=",
			"PANEL_SERVICE_NAME=",
			"PANEL_SMTP_HOST=",
			"PANEL_SMTP_PORT=",
			"PANEL_SMTP_USERNAME=",
			"PANEL_SMTP_PASSWORD=",
			"PANEL_SMTP_FROM=",
			"PANEL_SMTP_TO=",
			"PANEL_OPENAI_API_KEY=",
			"PANEL_OPENAI_MODEL=",
			"PANEL_MYSQL_ADMIN_DEFAULTS_FILE=",
			"PANEL_DATABASE_RESTORE_MAX_MB=",
			"PANEL_NGINX_BINARY=",
			"PANEL_NGINX_AVAILABLE_DIR=",
			"PANEL_NGINX_ENABLED_DIR=",
			"PANEL_SUBDOMAIN_ROOT_BASE=",
			"PANEL_CERTBOT_BINARY=",
			"PANEL_HELPER_BINARY=",
			"PANEL_AWS_ACCESS_KEY_ID=",
			"PANEL_AWS_SECRET_ACCESS_KEY=",
		}

		for _, key := range expectedKeys {
			if !strings.Contains(output, key) {
				t.Errorf("ToEnv() output missing expected key prefix %q", key)
			}
		}
	})

	t.Run("output ends with newline", func(t *testing.T) {
		cfg := Config{AppName: "Test"}
		output := cfg.ToEnv()
		if !strings.HasSuffix(output, "\n") {
			t.Error("ToEnv() output should end with a newline")
		}
	})

	t.Run("round-trip: write to temp file, load it, verify key values", func(t *testing.T) {
		cfg := Config{
			AppName:                "RoundTripPanel",
			Environment:            "staging",
			ListenAddr:             ":7070",
			BaseURL:                "https://staging.example.com",
			DatabaseRestoreMaxBytes: 128 * (1 << 20),
			NginxBinary:            "nginx",
			PAMService:             "sshd",
			SessionCookieName:      "rt_session",
			ServiceName:            "rt-service",
			SMTPPort:               "465",
			OpenAIModel:            "gpt-4",
			MySQLAdminDefaultsFile: "/tmp/mysql.cnf",
			NginxAvailableDir:      "/etc/nginx/sites-available",
			NginxEnabledDir:        "/etc/nginx/sites-enabled",
			CertbotBinary:          "certbot",
			HelperBinary:           "/usr/local/bin/helper",
			BootstrapUser:          "superadmin",
		}

		dir := t.TempDir()
		envFile := filepath.Join(dir, "panel.env")

		if err := os.WriteFile(envFile, []byte(cfg.ToEnv()), 0o600); err != nil {
			t.Fatalf("failed to write ToEnv output: %v", err)
		}

		// Pre-set env keys that loadEnvFile will overwrite so t.Setenv tracks them.
		t.Setenv("PANEL_APP_NAME", "")
		t.Setenv("PANEL_ENV", "")
		t.Setenv("PANEL_LISTEN_ADDR", "")
		t.Setenv("PANEL_BASE_URL", "")
		t.Setenv("PANEL_DATABASE_RESTORE_MAX_MB", "")

		if err := loadEnvFile(envFile); err != nil {
			t.Fatalf("loadEnvFile returned error: %v", err)
		}

		checks := []struct {
			key  string
			want string
		}{
			{"PANEL_APP_NAME", "RoundTripPanel"},
			{"PANEL_ENV", "staging"},
			{"PANEL_LISTEN_ADDR", ":7070"},
			{"PANEL_BASE_URL", "https://staging.example.com"},
			{"PANEL_DATABASE_RESTORE_MAX_MB", "128"},
		}

		for _, ch := range checks {
			if got := os.Getenv(ch.key); got != ch.want {
				t.Errorf("after round-trip, %s = %q; want %q", ch.key, got, ch.want)
			}
		}
	})
}
