//go:build linux

package system

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
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
var mysqlBindAddressPattern = regexp.MustCompile(`^[a-zA-Z0-9:._-]{1,255}$`)

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
			Name:             strings.TrimSpace(parts[0]),
			Engine:           strings.TrimSpace(parts[1]),
			RowCount:         rowCount,
			DataSize:         dataSize,
			IndexSize:        indexSize,
			DataSizeDisplay:  formatDatabaseBytes(dataSize),
			IndexSizeDisplay: formatDatabaseBytes(indexSize),
			TotalSizeDisplay: formatDatabaseBytes(dataSize + indexSize),
		})
		details.ApproximateSize += dataSize + indexSize
	}
	details.ApproximateSizeDisplay = formatDatabaseBytes(details.ApproximateSize)

	if len(details.Tables) == 0 {
		return details, nil
	}
	if selectedTable == "" || !databaseTableExists(details.Tables, selectedTable) {
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

func (m mysqlDatabaseManager) InspectService() (MySQLServiceStatus, error) {
	status := MySQLServiceStatus{
		ServiceName:       detectMySQLServiceName(),
		ConfigPath:        detectMySQLManagedConfigPath(),
		AdminDefaultsFile: m.adminDefaultsFile,
	}

	if output, err := exec.Command("mysql", "--version").CombinedOutput(); err == nil {
		status.Installed = true
		status.Version = strings.TrimSpace(string(output))
	}
	if status.ServiceName != "" {
		if systemdUnitExists(status.ServiceName) {
			status.Installed = true
		}
		status.Active = systemctlCheck("is-active", status.ServiceName)
		status.Enabled = systemctlCheck("is-enabled", status.ServiceName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	variables, err := m.readNamedValues(ctx, "SHOW GLOBAL VARIABLES", []string{
		"max_connections",
		"max_user_connections",
		"wait_timeout",
		"interactive_timeout",
		"max_connect_errors",
		"thread_cache_size",
		"table_open_cache",
		"port",
		"bind_address",
		"slow_query_log",
		"slow_query_log_file",
		"long_query_time",
		"innodb_buffer_pool_size",
	})
	if err != nil {
		return status, err
	}
	serverStatus, err := m.readNamedValues(ctx, "SHOW GLOBAL STATUS", []string{
		"threads_connected",
		"max_used_connections",
		"aborted_connects",
	})
	if err != nil {
		return status, err
	}

	status.CurrentConnections = parseMySQLInt(variablesOrStatusValue(serverStatus, "threads_connected"))
	status.MaxConnections = parseMySQLInt(variablesOrStatusValue(variables, "max_connections"))
	status.MaxUsedConnections = parseMySQLInt(variablesOrStatusValue(serverStatus, "max_used_connections"))
	status.MaxUserConnections = parseMySQLInt(variablesOrStatusValue(variables, "max_user_connections"))
	status.AbortedConnects = parseMySQLInt(variablesOrStatusValue(serverStatus, "aborted_connects"))
	status.WaitTimeout = parseMySQLInt(variablesOrStatusValue(variables, "wait_timeout"))
	status.InteractiveTimeout = parseMySQLInt(variablesOrStatusValue(variables, "interactive_timeout"))
	status.MaxConnectErrors = parseMySQLInt(variablesOrStatusValue(variables, "max_connect_errors"))
	status.ThreadCacheSize = parseMySQLInt(variablesOrStatusValue(variables, "thread_cache_size"))
	status.TableOpenCache = parseMySQLInt(variablesOrStatusValue(variables, "table_open_cache"))
	status.Port = parseMySQLInt(variablesOrStatusValue(variables, "port"))
	status.BindAddress = variablesOrStatusValue(variables, "bind_address")
	status.SlowQueryLogEnabled = parseMySQLBool(variablesOrStatusValue(variables, "slow_query_log"))
	status.SlowQueryLogFile = variablesOrStatusValue(variables, "slow_query_log_file")
	status.LongQueryTimeSeconds = variablesOrStatusValue(variables, "long_query_time")
	status.TopUsers, _ = m.inspectTopConnectionUsers(ctx)
	status.TopOperations, _ = m.inspectTopConnectionOperations(ctx)
	status.InnodbBufferPoolSizeBytes = parseMySQLInt64(variablesOrStatusValue(variables, "innodb_buffer_pool_size"))
	status.InnodbBufferPoolSizeDisplay = formatDatabaseBytes(status.InnodbBufferPoolSizeBytes)
	if status.Port <= 0 {
		status.Port = 3306
	}

	return status, nil
}

func (m mysqlDatabaseManager) ConfigureService(spec MySQLServiceConfigSpec) (string, error) {
	if spec.MaxConnections <= 0 || spec.MaxConnections > 100000 {
		return "", ErrInvalidMySQLMaxConnections
	}
	if spec.MaxUserConnections < 0 || spec.MaxUserConnections > 100000 {
		return "", ErrInvalidMySQLMaxUserConnections
	}
	if spec.WaitTimeout <= 0 {
		return "", ErrInvalidMySQLWaitTimeout
	}
	if spec.InteractiveTimeout <= 0 {
		return "", ErrInvalidMySQLInteractiveTimeout
	}
	if spec.MaxConnectErrors <= 0 {
		return "", ErrInvalidMySQLMaxConnectErrors
	}
	if spec.ThreadCacheSize < 0 {
		return "", ErrInvalidMySQLThreadCacheSize
	}
	if spec.TableOpenCache <= 0 {
		return "", ErrInvalidMySQLTableOpenCache
	}
	if spec.InnodbBufferPoolSizeMB <= 0 {
		return "", ErrInvalidMySQLBufferPoolSize
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return "", ErrInvalidMySQLPort
	}
	bindAddress := strings.TrimSpace(spec.BindAddress)
	if !isValidMySQLBindAddress(bindAddress) {
		return "", ErrInvalidMySQLBindAddress
	}
	longQueryTime := strings.TrimSpace(spec.LongQueryTimeSeconds)
	if _, err := strconv.ParseFloat(longQueryTime, 64); err != nil || longQueryTime == "" {
		return "", ErrInvalidMySQLLongQueryTime
	}
	slowQueryLogFile := strings.TrimSpace(spec.SlowQueryLogFile)
	if spec.SlowQueryLogEnabled {
		if !filepath.IsAbs(slowQueryLogFile) {
			return "", ErrInvalidMySQLSlowQueryLogPath
		}
		if err := os.MkdirAll(filepath.Dir(slowQueryLogFile), 0o755); err != nil {
			return "", fmt.Errorf("create mysql slow query log directory: %w", err)
		}
	}

	configPath := detectMySQLManagedConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return "", fmt.Errorf("create mysql config directory: %w", err)
	}

	content := strings.Join([]string{
		"[mysqld]",
		fmt.Sprintf("max_connections=%d", spec.MaxConnections),
		fmt.Sprintf("max_user_connections=%d", spec.MaxUserConnections),
		fmt.Sprintf("wait_timeout=%d", spec.WaitTimeout),
		fmt.Sprintf("interactive_timeout=%d", spec.InteractiveTimeout),
		fmt.Sprintf("max_connect_errors=%d", spec.MaxConnectErrors),
		fmt.Sprintf("thread_cache_size=%d", spec.ThreadCacheSize),
		fmt.Sprintf("table_open_cache=%d", spec.TableOpenCache),
		fmt.Sprintf("port=%d", spec.Port),
		fmt.Sprintf("bind-address=%s", bindAddress),
		fmt.Sprintf("slow_query_log=%s", mysqlConfigBool(spec.SlowQueryLogEnabled)),
		fmt.Sprintf("slow_query_log_file=%s", slowQueryLogFile),
		fmt.Sprintf("long_query_time=%s", longQueryTime),
		fmt.Sprintf("innodb_buffer_pool_size=%dM", spec.InnodbBufferPoolSizeMB),
		"",
	}, "\n")

	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write mysql managed config: %w", err)
	}

	return fmt.Sprintf("MySQL service overrides saved to %s\nRestart %s to apply the persistent configuration.", configPath, firstNonEmptyString(detectMySQLServiceName(), "mysql")), nil
}

func (m mysqlDatabaseManager) InstallService() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := `set -euo pipefail
apt-get update
if apt-cache show mysql-server >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server
elif apt-cache show mariadb-server >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server
else
  echo "No mysql-server or mariadb-server package is available on this host." >&2
  exit 1
fi
svc=""
for candidate in mysql mariadb mysqld; do
  if systemctl list-unit-files "${candidate}.service" --no-legend --no-pager 2>/dev/null | grep -q .; then
    svc="$candidate"
    break
  fi
done
if [ -z "$svc" ]; then svc="mysql"; fi
systemctl enable "$svc" || true
systemctl restart "$svc"
systemctl show "$svc" --property=ActiveState --property=SubState --property=UnitFileState --no-pager`
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("install mysql service: %w", err)
	}
	return result, nil
}

func (m mysqlDatabaseManager) UpgradeService() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := `set -euo pipefail
apt-get update
pkg=""
if dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -q "install ok installed"; then
  pkg="mysql-server"
elif dpkg-query -W -f='${Status}' mariadb-server 2>/dev/null | grep -q "install ok installed"; then
  pkg="mariadb-server"
elif apt-cache show mysql-server >/dev/null 2>&1; then
  pkg="mysql-server"
elif apt-cache show mariadb-server >/dev/null 2>&1; then
  pkg="mariadb-server"
else
  echo "No mysql-server or mariadb-server package is available on this host." >&2
  exit 1
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$pkg" || DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
svc=""
for candidate in mysql mariadb mysqld; do
  if systemctl list-unit-files "${candidate}.service" --no-legend --no-pager 2>/dev/null | grep -q .; then
    svc="$candidate"
    break
  fi
done
if [ -z "$svc" ]; then svc="mysql"; fi
systemctl restart "$svc"
systemctl show "$svc" --property=ActiveState --property=SubState --property=UnitFileState --no-pager`
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("upgrade mysql service: %w", err)
	}
	return result, nil
}

func (m mysqlDatabaseManager) StartService() (string, error) {
	return runMySQLServiceCommand("start", detectMySQLServiceName())
}

func (m mysqlDatabaseManager) StopService() (string, error) {
	return runMySQLServiceCommand("stop", detectMySQLServiceName())
}

func (m mysqlDatabaseManager) RestartService() (string, error) {
	return runMySQLServiceCommand("restart", detectMySQLServiceName())
}

func (m mysqlDatabaseManager) ServiceLogs(lines int) (string, error) {
	if lines <= 0 || lines > 2000 {
		return "", ErrInvalidMySQLLogLines
	}
	status, err := m.InspectService()
	if err != nil {
		return "", err
	}
	serviceName := firstNonEmptyString(status.ServiceName, detectMySQLServiceName(), "mysql")
	slowQuerySection := ""
	if status.SlowQueryLogEnabled && filepath.IsAbs(strings.TrimSpace(status.SlowQueryLogFile)) {
		slowQuerySection = fmt.Sprintf(`
printf '\n=== Slow Query Log (%s) ===\n'
if [ -f %q ]; then
  tail -n %d %q
else
  echo 'Slow query log file not found.'
fi
`, status.SlowQueryLogFile, status.SlowQueryLogFile, lines, status.SlowQueryLogFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := fmt.Sprintf(`set -euo pipefail
printf '=== Service Log (%s) ===\n'
if command -v journalctl >/dev/null 2>&1; then
  journalctl -u %s -n %d --no-pager
else
  for candidate in /var/log/mysql/error.log /var/log/mysql/mysql-error.log /var/log/mysqld.log; do
    if [ -f "$candidate" ]; then
      tail -n %d "$candidate"
      exit 0
    fi
  done
  echo 'No MySQL log file was found.'
fi
%s`, serviceName, serviceName, lines, lines, slowQuerySection)
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("read mysql logs: %w", err)
	}
	return result, nil
}

func (m mysqlDatabaseManager) ExecuteAdminQuery(statement string, maxRows int) (DatabaseQueryResult, error) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return DatabaseQueryResult{}, ErrInvalidDatabaseQuery
	}
	if maxRows <= 0 || maxRows > 500 {
		maxRows = 250
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{
		"--defaults-extra-file=" + m.adminDefaultsFile,
		"--batch",
		"--raw",
		"--execute",
		statement,
	}
	return runMySQLBatchQuery(ctx, args, maxRows)
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

func ExecuteDatabaseQuery(adminDefaultsFile string, databaseName string, statement string, maxRows int) (DatabaseQueryResult, error) {
	manager := mysqlDatabaseManager{adminDefaultsFile: adminDefaultsFile}
	return manager.executeQuery(databaseName, statement, maxRows)
}

func ExportDatabase(adminDefaultsFile string, databaseName string, filePath string) (string, error) {
	manager := mysqlDatabaseManager{adminDefaultsFile: adminDefaultsFile}
	return manager.exportDatabase(databaseName, filePath)
}

func (m mysqlDatabaseManager) executeQuery(databaseName string, statement string, maxRows int) (DatabaseQueryResult, error) {
	databaseName = strings.TrimSpace(databaseName)
	statement = strings.TrimSpace(statement)
	if !mysqlProvisionNamePattern.MatchString(databaseName) {
		return DatabaseQueryResult{}, ErrInvalidDatabaseName
	}
	if statement == "" {
		return DatabaseQueryResult{}, ErrInvalidDatabaseQuery
	}
	if maxRows <= 0 || maxRows > 500 {
		maxRows = 250
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{
		"--defaults-extra-file=" + m.adminDefaultsFile,
		"--database=" + databaseName,
		"--batch",
		"--raw",
		"--execute",
		statement,
	}
	return runMySQLBatchQuery(ctx, args, maxRows)
}

func (m mysqlDatabaseManager) exportDatabase(databaseName string, filePath string) (string, error) {
	databaseName = strings.TrimSpace(databaseName)
	filePath = strings.TrimSpace(filePath)
	if !mysqlProvisionNamePattern.MatchString(databaseName) {
		return "", ErrInvalidDatabaseName
	}
	if !filepath.IsAbs(filePath) {
		return "", ErrInvalidRestorePath
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return "", err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	args := []string{
		"--defaults-extra-file=" + m.adminDefaultsFile,
		"--single-transaction",
		"--routines",
		"--triggers",
		"--events",
		databaseName,
	}
	cmd := exec.CommandContext(ctx, "mysqldump", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	if _, err := io.Copy(gzipWriter, stdout); err != nil {
		_ = cmd.Process.Kill()
		return "", err
	}
	stderrBytes, _ := io.ReadAll(stderr)
	if err := gzipWriter.Close(); err != nil {
		return "", err
	}
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("mysqldump failed: %w: %s", err, strings.TrimSpace(string(stderrBytes)))
	}
	return filePath, nil
}

func formatDatabaseBytes(size int64) string {
	if size <= 0 {
		return "0 MB"
	}
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	if size >= gb {
		return fmt.Sprintf("%.2f GB", float64(size)/float64(gb))
	}
	if size >= mb {
		return fmt.Sprintf("%.2f MB", float64(size)/float64(mb))
	}
	if size >= kb {
		return fmt.Sprintf("%.2f KB", float64(size)/float64(kb))
	}
	return fmt.Sprintf("%d B", size)
}

func databaseTableExists(tables []DatabaseTableSummary, name string) bool {
	for _, table := range tables {
		if table.Name == name {
			return true
		}
	}
	return false
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

func runMySQLBatchQuery(ctx context.Context, args []string, maxRows int) (DatabaseQueryResult, error) {
	cmd := exec.CommandContext(ctx, "mysql", args...)
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		return DatabaseQueryResult{}, fmt.Errorf("mysql query failed: %w: %s", err, trimmed)
	}
	result := DatabaseQueryResult{Message: firstNonEmptyString(trimmed, "Query executed successfully.")}
	if trimmed == "" {
		return result, nil
	}
	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	if !scanner.Scan() {
		return result, nil
	}
	result.Columns = strings.Split(scanner.Text(), "\t")
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(result.Rows) >= maxRows {
			result.Truncated = true
			break
		}
		result.Rows = append(result.Rows, strings.Split(line, "\t"))
	}
	if err := scanner.Err(); err != nil {
		return DatabaseQueryResult{}, err
	}
	if len(result.Columns) > 0 {
		result.RowCount = len(result.Rows)
		if result.Truncated {
			result.Message = fmt.Sprintf("Showing the first %d rows returned by the query.", maxRows)
		} else if result.RowCount > 0 {
			result.Message = fmt.Sprintf("Query returned %d rows.", result.RowCount)
		} else {
			result.Message = "Query returned no rows."
		}
	}
	return result, nil
}

func (m mysqlDatabaseManager) readNamedValues(ctx context.Context, prefix string, names []string) (map[string]string, error) {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, mysqlQuoteString(strings.ToLower(strings.TrimSpace(name))))
	}
	query := fmt.Sprintf("%s WHERE Variable_name IN (%s)", prefix, strings.Join(quoted, ","))
	output, err := m.runMySQL(ctx, query)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(names))
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		values[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	}
	return values, nil
}

func variablesOrStatusValue(values map[string]string, key string) string {
	if values == nil {
		return ""
	}
	return strings.TrimSpace(values[strings.ToLower(strings.TrimSpace(key))])
}

func parseMySQLInt(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func parseMySQLInt64(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

func parseMySQLBool(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "1" || value == "on" || value == "yes" || value == "true"
}

func isValidMySQLBindAddress(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	if strings.EqualFold(value, "localhost") {
		return true
	}
	return mysqlBindAddressPattern.MatchString(value)
}

func mysqlConfigBool(value bool) string {
	if value {
		return "ON"
	}
	return "OFF"
}

func (m mysqlDatabaseManager) inspectTopConnectionUsers(ctx context.Context) ([]MySQLConnectionUserSummary, error) {
	output, err := m.runMySQL(ctx, "SELECT COALESCE(USER,'system') AS user_name, COALESCE(SUBSTRING_INDEX(HOST,':',1),'') AS host_name, COUNT(*) AS connection_count FROM information_schema.processlist GROUP BY user_name, host_name ORDER BY connection_count DESC, user_name ASC LIMIT 10")
	if err != nil {
		return nil, err
	}
	items := make([]MySQLConnectionUserSummary, 0)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		items = append(items, MySQLConnectionUserSummary{
			Username:    strings.TrimSpace(parts[0]),
			Host:        strings.TrimSpace(parts[1]),
			Connections: parseMySQLInt(parts[2]),
		})
	}
	return items, nil
}

func (m mysqlDatabaseManager) inspectTopConnectionOperations(ctx context.Context) ([]MySQLConnectionOperationSummary, error) {
	query := "SELECT COALESCE(COMMAND,'unknown') AS command_name, COALESCE(DB,'') AS database_name, COALESCE(NULLIF(STATE,''),'idle') AS state_name, COUNT(*) AS connection_count, COALESCE(MAX(LEFT(INFO,160)),'') AS example_query FROM information_schema.processlist GROUP BY command_name, database_name, state_name ORDER BY connection_count DESC, command_name ASC LIMIT 10"
	output, err := m.runMySQL(ctx, query)
	if err != nil {
		return nil, err
	}
	items := make([]MySQLConnectionOperationSummary, 0)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		items = append(items, MySQLConnectionOperationSummary{
			Command:      strings.TrimSpace(parts[0]),
			DatabaseName: strings.TrimSpace(parts[1]),
			State:        strings.TrimSpace(parts[2]),
			Connections:  parseMySQLInt(parts[3]),
			ExampleQuery: strings.TrimSpace(parts[4]),
		})
	}
	return items, nil
}

func detectMySQLServiceName() string {
	for _, candidate := range []string{"mysql", "mariadb", "mysqld"} {
		if systemctlCheck("is-active", candidate) || systemctlCheck("is-enabled", candidate) || systemdUnitExists(candidate) {
			return candidate
		}
	}
	return "mysql"
}

func detectMySQLManagedConfigPath() string {
	for _, dir := range []string{"/etc/mysql/conf.d", "/etc/mysql/mysql.conf.d", "/etc/my.cnf.d"} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return filepath.Join(dir, "server-side-control.cnf")
		}
	}
	if info, err := os.Stat("/etc/mysql"); err == nil && info.IsDir() {
		return "/etc/mysql/conf.d/server-side-control.cnf"
	}
	return "/etc/my.cnf.d/server-side-control.cnf"
}

func systemdUnitExists(service string) bool {
	service = strings.TrimSpace(service)
	if service == "" {
		return false
	}
	output, err := exec.Command("systemctl", "list-unit-files", service+".service", "--no-legend", "--no-pager").CombinedOutput()
	if err != nil {
		return false
	}
	trimmed := strings.TrimSpace(string(output))
	return trimmed != "" && !strings.Contains(trimmed, "0 unit files listed")
}

func runMySQLServiceCommand(action string, service string) (string, error) {
	service = firstNonEmptyString(strings.TrimSpace(service), "mysql")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-lc", fmt.Sprintf("set -euo pipefail\nsystemctl %s %s\nsystemctl show %s --property=ActiveState --property=SubState --property=UnitFileState --no-pager", action, service, service))
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("mysql service %s failed: %w", action, err)
	}
	return result, nil
}
