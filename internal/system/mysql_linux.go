//go:build linux

package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var mysqlProvisionNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
var mysqlTableNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

var ErrInvalidDatabaseName = errors.New("invalid mysql database name")
var ErrInvalidUserName = errors.New("invalid mysql user name")
var ErrInvalidPassword = errors.New("invalid mysql password")

type mysqlAdminDefaults struct {
	User     string
	Password string
	Host     string
	Port     string
	Protocol string
	Socket   string
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

func (m mysqlDatabaseManager) ListDatabaseAccess() ([]DatabaseAccess, error) {
	if !filepath.IsAbs(m.adminDefaultsFile) {
		return nil, fmt.Errorf("mysql admin defaults file path must be absolute")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	databasesOutput, err := m.runMySQL(ctx, `SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema','mysql','performance_schema','sys') ORDER BY schema_name`)
	if err != nil {
		return nil, err
	}

	grantsOutput, err := m.runMySQL(ctx, `SELECT Db, User, Host FROM mysql.db WHERE Db NOT IN ('information_schema','mysql','performance_schema','sys') ORDER BY Db, User, Host`)
	if err != nil {
		return nil, err
	}

	entries := make([]DatabaseAccess, 0)
	seen := make(map[string]struct{})

	for _, line := range strings.Split(strings.TrimSpace(grantsOutput), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		entry := DatabaseAccess{DatabaseName: strings.TrimSpace(parts[0]), Username: strings.TrimSpace(parts[1]), Host: strings.TrimSpace(parts[2])}
		key := entry.DatabaseName + "|" + entry.Username + "|" + entry.Host
		seen[key] = struct{}{}
		entries = append(entries, entry)
	}

	for _, line := range strings.Split(strings.TrimSpace(databasesOutput), "\n") {
		databaseName := strings.TrimSpace(line)
		if databaseName == "" {
			continue
		}
		if hasDatabaseEntry(entries, databaseName) {
			continue
		}
		key := databaseName + "||"
		if _, ok := seen[key]; ok {
			continue
		}
		entries = append(entries, DatabaseAccess{DatabaseName: databaseName})
	}

	sort.Slice(entries, func(i int, j int) bool {
		if entries[i].DatabaseName == entries[j].DatabaseName {
			if entries[i].Username == entries[j].Username {
				return entries[i].Host < entries[j].Host
			}
			return entries[i].Username < entries[j].Username
		}
		return entries[i].DatabaseName < entries[j].DatabaseName
	})

	return entries, nil
}

func (m mysqlDatabaseManager) DeleteDatabaseAccess(name string, username string, host string, dropDatabase bool) error {
	name = strings.TrimSpace(name)
	username = strings.TrimSpace(username)
	host = strings.TrimSpace(host)
	if !mysqlProvisionNamePattern.MatchString(name) {
		return ErrInvalidDatabaseName
	}
	if username != "" && !mysqlProvisionNamePattern.MatchString(username) {
		return ErrInvalidUserName
	}
	if host == "" {
		host = "%"
	}

	statements := make([]string, 0, 4)
	if username != "" {
		statements = append(statements,
			fmt.Sprintf("REVOKE ALL PRIVILEGES, GRANT OPTION FROM %s", mysqlQuoteAccountParts(username, host)),
			fmt.Sprintf("DROP USER IF EXISTS %s", mysqlQuoteAccountParts(username, host)),
		)
	}
	if dropDatabase {
		statements = append(statements, fmt.Sprintf("DROP DATABASE IF EXISTS %s", mysqlQuoteIdentifier(name)))
	}
	statements = append(statements, "FLUSH PRIVILEGES")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := m.runMySQL(ctx, strings.Join(statements, "; "))
	return err
}

func (m mysqlDatabaseManager) RotateUserPassword(username string, host string, password string) error {
	username = strings.TrimSpace(username)
	host = strings.TrimSpace(host)
	password = strings.TrimSpace(password)
	if !mysqlProvisionNamePattern.MatchString(username) {
		return ErrInvalidUserName
	}
	if password == "" {
		return ErrInvalidPassword
	}
	if host == "" {
		host = "%"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := m.runMySQL(ctx, fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s", mysqlQuoteAccountParts(username, host), mysqlQuoteString(password)))
	return err
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

func (m mysqlDatabaseManager) InspectDatabase(spec DatabaseInspectSpec) (DatabaseDetails, error) {
	databaseName := strings.TrimSpace(spec.DatabaseName)
	if !mysqlProvisionNamePattern.MatchString(databaseName) {
		return DatabaseDetails{}, ErrInvalidDatabaseName
	}
	selectedTable := strings.TrimSpace(spec.TableName)
	if selectedTable != "" && !mysqlTableNamePattern.MatchString(selectedTable) {
		return DatabaseDetails{}, ErrInvalidTableName
	}
	if spec.Limit <= 0 || spec.Limit > 100 {
		spec.Limit = 25
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := fmt.Sprintf("SELECT table_name, COALESCE(engine,''), COALESCE(table_rows,0), COALESCE(data_length,0), COALESCE(index_length,0) FROM information_schema.tables WHERE table_schema = %s ORDER BY table_name", mysqlQuoteString(databaseName))
	output, err := m.runMySQL(ctx, query)
	if err != nil {
		return DatabaseDetails{}, err
	}

	details := DatabaseDetails{DatabaseName: databaseName}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		rowCount, _ := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		dataSize, _ := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
		indexSize, _ := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
		details.Tables = append(details.Tables, DatabaseTableSummary{
			Name:      strings.TrimSpace(parts[0]),
			Engine:    strings.TrimSpace(parts[1]),
			RowCount:  rowCount,
			DataSize:  dataSize,
			IndexSize: indexSize,
		})
		details.ApproximateSize += dataSize + indexSize
	}

	if len(details.Tables) == 0 {
		return details, nil
	}
	if selectedTable == "" {
		selectedTable = details.Tables[0].Name
	}
	details.SelectedTable = selectedTable
	preview, err := m.previewTable(ctx, databaseName, selectedTable, spec.Limit)
	if err != nil {
		return details, err
	}
	details.Preview = preview
	return details, nil
}

func (m mysqlDatabaseManager) RestoreDatabase(name string, filePath string) (string, error) {
	name = strings.TrimSpace(name)
	filePath = strings.TrimSpace(filePath)
	if !mysqlProvisionNamePattern.MatchString(name) {
		return "", ErrInvalidDatabaseName
	}
	if !filepath.IsAbs(filePath) {
		return "", ErrInvalidRestorePath
	}
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{
		"--defaults-extra-file=" + m.adminDefaultsFile,
		"--database=" + name,
	}
	cmd := exec.CommandContext(ctx, "mysql", args...)
	cmd.Stdin = file
	output, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(output)), fmt.Errorf("mysql restore failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
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

func (m mysqlDatabaseManager) previewTable(ctx context.Context, databaseName string, tableName string, limit int) (DatabaseTablePreview, error) {
	if !mysqlTableNamePattern.MatchString(tableName) {
		return DatabaseTablePreview{}, ErrInvalidTableName
	}
	columnsQuery := fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position", mysqlQuoteString(databaseName), mysqlQuoteString(tableName))
	columnsOutput, err := m.runMySQL(ctx, columnsQuery)
	if err != nil {
		return DatabaseTablePreview{}, err
	}
	preview := DatabaseTablePreview{Name: tableName}
	for _, line := range strings.Split(strings.TrimSpace(columnsOutput), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		preview.Columns = append(preview.Columns, line)
	}
	if len(preview.Columns) == 0 {
		return preview, nil
	}
	rowsQuery := fmt.Sprintf("SELECT * FROM %s.%s LIMIT %d", mysqlQuoteIdentifier(databaseName), mysqlQuoteIdentifier(tableName), limit)
	rowsOutput, err := m.runMySQL(ctx, rowsQuery)
	if err != nil {
		return preview, err
	}
	scanner := bufio.NewScanner(strings.NewReader(rowsOutput))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		preview.Rows = append(preview.Rows, strings.Split(line, "\t"))
	}
	return preview, scanner.Err()
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
		case "socket":
			defaults.Socket = value
		}
	}

	if defaults.User == "" {
		return mysqlAdminDefaults{}, fmt.Errorf("mysql admin defaults file is missing user")
	}
	if defaults.Socket == "" && defaults.Host == "" {
		defaults.Host = "127.0.0.1"
	}
	if defaults.Socket == "" && defaults.Port == "" {
		defaults.Port = "3306"
	}
	if defaults.Socket == "" && defaults.Protocol == "" {
		defaults.Protocol = "tcp"
	}

	return defaults, nil
}

func writeMySQLAdminDefaults(path string, defaults mysqlAdminDefaults) error {
	content := strings.Join([]string{
		"[client]",
		fmt.Sprintf("user=%s", defaults.User),
		mysqlDefaultsLine("password", defaults.Password),
		mysqlDefaultsLine("host", defaults.Host),
		mysqlDefaultsLine("port", defaults.Port),
		mysqlDefaultsLine("protocol", defaults.Protocol),
		mysqlDefaultsLine("socket", defaults.Socket),
		"",
	}, "\n")

	return os.WriteFile(path, []byte(content), 0o600)
}

func mysqlDefaultsLine(key string, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return fmt.Sprintf("%s=%s", key, value)
}

func mysqlQuoteAccount(value string) string {
	parts := strings.SplitN(strings.TrimSpace(value), "@", 2)
	if len(parts) != 2 {
		return mysqlQuoteIdentifier(value) + "@'%'"
	}
	return mysqlQuoteIdentifier(parts[0]) + "@" + mysqlQuoteString(parts[1])
}

func mysqlQuoteAccountParts(username string, host string) string {
	return mysqlQuoteIdentifier(username) + "@" + mysqlQuoteString(host)
}

func hasDatabaseEntry(entries []DatabaseAccess, databaseName string) bool {
	for _, entry := range entries {
		if entry.DatabaseName == databaseName {
			return true
		}
	}
	return false
}

func mysqlQuoteIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "") + "`"
}

func mysqlQuoteString(value string) string {
	replacer := strings.NewReplacer(`\\`, `\\\\`, `'`, `\\'`)
	return "'" + replacer.Replace(value) + "'"
}