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

var mysqlProvisionNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

var ErrInvalidDatabaseName = errors.New("invalid mysql database name")
var ErrInvalidUserName = errors.New("invalid mysql user name")
var ErrInvalidPassword = errors.New("invalid mysql password")

type mysqlAdminDefaults struct {
	User     string
	Password string
	Host     string
	Port     string
	Protocol string
}

type mysqlDatabaseManager struct {
	adminDefaultsFile string
}

func NewDatabaseManager(adminDefaultsFile string) DatabaseManager {
	if strings.TrimSpace(adminDefaultsFile) == "" {
		adminDefaultsFile = "/etc/server-side-control/mysql-admin.cnf"
	}
	return mysqlDatabaseManager{adminDefaultsFile: adminDefaultsFile}
}

func (m mysqlDatabaseManager) ProvisionDatabase(name string, username string, password string) error {
	name = strings.TrimSpace(name)
	username = strings.TrimSpace(username)
	if !mysqlProvisionNamePattern.MatchString(name) {
		return ErrInvalidDatabaseName
	}
	if !mysqlProvisionNamePattern.MatchString(username) {
		return ErrInvalidUserName
	}
	if !filepath.IsAbs(m.adminDefaultsFile) {
		return fmt.Errorf("mysql admin defaults file path must be absolute")
	}

	statements := []string{
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", mysqlQuoteIdentifier(name)),
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s@'%%' IDENTIFIED BY %s", mysqlQuoteIdentifier(username), mysqlQuoteString(password)),
		fmt.Sprintf("ALTER USER %s@'%%' IDENTIFIED BY %s", mysqlQuoteIdentifier(username), mysqlQuoteString(password)),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO %s@'%%'", mysqlQuoteIdentifier(name), mysqlQuoteIdentifier(username)),
		"FLUSH PRIVILEGES",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := m.runMySQL(ctx, strings.Join(statements, "; ")); err != nil {
		return err
	}

	return nil
}

func (m mysqlDatabaseManager) RotateAdminPassword(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return ErrInvalidPassword
	}
	if !filepath.IsAbs(m.adminDefaultsFile) {
		return fmt.Errorf("mysql admin defaults file path must be absolute")
	}

	defaults, err := readMySQLAdminDefaults(m.adminDefaultsFile)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	account, err := m.currentAccount(ctx)
	if err != nil {
		return err
	}

	statement := fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s", mysqlQuoteAccount(account), mysqlQuoteString(password))
	if _, err := m.runMySQL(ctx, statement); err != nil {
		return err
	}

	defaults.Password = password
	return writeMySQLAdminDefaults(m.adminDefaultsFile, defaults)
}

func (m mysqlDatabaseManager) currentAccount(ctx context.Context) (string, error) {
	output, err := m.runMySQL(ctx, "SELECT CURRENT_USER()")
	if err != nil {
		return "", err
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[len(lines)-1]) == "" {
		return "", fmt.Errorf("mysql current user query returned no account")
	}
	return strings.TrimSpace(lines[len(lines)-1]), nil
}

func (m mysqlDatabaseManager) runMySQL(ctx context.Context, statement string) (string, error) {
	args := []string{
		"--defaults-extra-file=" + m.adminDefaultsFile,
		"--batch",
		"--raw",
		"--skip-column-names",
		"--execute",
		statement,
	}
	cmd := exec.CommandContext(ctx, "mysql", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mysql command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func readMySQLAdminDefaults(path string) (mysqlAdminDefaults, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return mysqlAdminDefaults{}, err
	}

	defaults := mysqlAdminDefaults{Protocol: "tcp"}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "user":
			defaults.User = value
		case "password":
			defaults.Password = value
		case "host":
			defaults.Host = value
		case "port":
			defaults.Port = value
		case "protocol":
			defaults.Protocol = value
		}
	}

	if defaults.User == "" {
		return mysqlAdminDefaults{}, fmt.Errorf("mysql admin defaults file is missing user")
	}
	if defaults.Host == "" {
		defaults.Host = "127.0.0.1"
	}
	if defaults.Port == "" {
		defaults.Port = "3306"
	}
	if defaults.Protocol == "" {
		defaults.Protocol = "tcp"
	}

	return defaults, nil
}

func writeMySQLAdminDefaults(path string, defaults mysqlAdminDefaults) error {
	content := strings.Join([]string{
		"[client]",
		fmt.Sprintf("user=%s", defaults.User),
		fmt.Sprintf("password=%s", defaults.Password),
		fmt.Sprintf("host=%s", defaults.Host),
		fmt.Sprintf("port=%s", defaults.Port),
		fmt.Sprintf("protocol=%s", defaults.Protocol),
		"",
	}, "\n")

	return os.WriteFile(path, []byte(content), 0o600)
}

func mysqlQuoteAccount(value string) string {
	parts := strings.SplitN(strings.TrimSpace(value), "@", 2)
	if len(parts) != 2 {
		return mysqlQuoteIdentifier(value) + "@'%'"
	}
	return mysqlQuoteIdentifier(parts[0]) + "@" + mysqlQuoteString(parts[1])
}

func mysqlQuoteIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "") + "`"
}

func mysqlQuoteString(value string) string {
	replacer := strings.NewReplacer(`\\`, `\\\\`, `'`, `\\'`)
	return "'" + replacer.Replace(value) + "'"
}