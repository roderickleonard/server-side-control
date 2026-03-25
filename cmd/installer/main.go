package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/kaganyegin/server-side-control/internal/config"
	"github.com/kaganyegin/server-side-control/internal/store"
	"golang.org/x/term"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	envPath := os.Getenv("PANEL_ENV_FILE")
	if envPath == "" {
		envPath = filepath.Join("config", "panel.env")
	}

	fmt.Println("Server Side Control installer")
	fmt.Println("Leave a field blank to use the default value shown in brackets.")

	listenAddr := prompt(reader, "Panel listen address", ":8080", "Panel uygulamasinin sunucuda hangi IP/port uzerinde dinleyecegi. Nginx kullanacaksan genelde 127.0.0.1:8080 tercih edilir.")
	baseURL := prompt(reader, "Panel base URL", "http://127.0.0.1:8080", "Tarayicidan erisecegin tam panel adresi. Domain kullanacaksan ornek: https://panel.example.com")
	mysqlAdminHost := prompt(reader, "MySQL root host", "127.0.0.1", "MySQL servisinin calistigi host. Ayni sunucudaysa genelde 127.0.0.1")
	mysqlAdminPort := prompt(reader, "MySQL root port", "3306", "MySQL TCP portu. Varsayilan genelde 3306")
	mysqlAdminUser := prompt(reader, "MySQL root user", "root", "Panel veritabani ve MySQL kullanicilarini olusturmak icin kullanilacak admin hesap")
	mysqlAdminPassword := promptPassword(reader, "MySQL root password", "", "Yukaridaki MySQL admin kullanicisinin parolasi. Ubuntu'da root auth_socket kullaniyorsa bunu bos birakabilirsin.")
	mysqlAdminDefaultsFile := prompt(reader, "MySQL admin defaults file", "/etc/server-side-control/mysql-admin.cnf", "MySQL admin erisiminin root-only olarak saklanacagi dosya. Panel veritabani islemleri icin helper bunu kullanir.")
	panelDatabaseName := prompt(reader, "Panel MySQL database", "server_side_control", "Panelin kendi tablolarini tutacagi veritabani adi")
	panelDatabaseUser := prompt(reader, "Panel MySQL user", "server_side_control", "Panel uygulamasinin kendi veritabanina baglanirken kullanacagi MySQL kullanicisi")
	panelDatabasePassword := promptPassword(reader, "Panel MySQL user password", "", "Panel MySQL kullanicisinin parolasi. Bos birakirsan guclu bir parola uretilir.")
	generatedDatabasePassword := false
	if panelDatabasePassword == "" {
		secret, err := randomPassword(24)
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate panel MySQL password: %v\n", err)
			os.Exit(1)
		}
		panelDatabasePassword = secret
		generatedDatabasePassword = true
	}

	adminConnection := mysqlAdminConnection{
		User:     mysqlAdminUser,
		Password: mysqlAdminPassword,
		Host:     mysqlAdminHost,
		Port:     mysqlAdminPort,
	}
	adminDSN := adminConnection.DSN("mysql")
	databaseDSN := buildMySQLDSN(panelDatabaseUser, panelDatabasePassword, mysqlAdminHost, mysqlAdminPort, panelDatabaseName)
	bootstrapUser := prompt(reader, "Bootstrap panel user", "admin", "PAM disinda panel icine ilk giris icin kullanacagin gecici veya kalici yonetici kullanici adi")
	bootstrapPassword := promptPassword(reader, "Bootstrap panel password", "change-me", "Bootstrap panel kullanicisinin parolasi. Bunu guclu bir degerle degistirmen daha dogru olur.")
	pamService := prompt(reader, "PAM service name", "login", "Ubuntu kullanicilariyla giris icin kullanilacak PAM servis adi. Genelde login yeterlidir.")
	nginxBinary := prompt(reader, "Nginx binary", "nginx", "Nginx komutunun yolu veya binary adi")
	nginxAvailableDir := prompt(reader, "Nginx sites-available dir", "/etc/nginx/sites-available", "Nginx sanal host dosyalarinin yazilacagi dizin")
	nginxEnabledDir := prompt(reader, "Nginx sites-enabled dir", "/etc/nginx/sites-enabled", "Aktif Nginx site linklerinin bulunacagi dizin")
	certbotBinary := prompt(reader, "Certbot binary", "certbot", "TLS sertifikasi almak icin kullanilacak certbot komutu")
	helperBinary := prompt(reader, "Privileged helper binary", "/usr/local/bin/server-side-control-helper", "Root gerektiren islemleri yapan helper binary'nin tam yolu")

	if err := provisionPanelDatabase(adminDSN, mysqlAdminHost, mysqlAdminPort, panelDatabaseName, panelDatabaseUser, panelDatabasePassword); err != nil {
		if fallback, fallbackErr := fallbackToSocketAuth(adminConnection, err); fallbackErr == nil {
			adminConnection = fallback
			adminDSN = adminConnection.DSN("mysql")
			fmt.Printf("\nMySQL admin login switched to local socket auth: %s\n", adminConnection.Socket)
			if retryErr := provisionPanelDatabase(adminDSN, mysqlAdminHost, mysqlAdminPort, panelDatabaseName, panelDatabaseUser, panelDatabasePassword); retryErr != nil {
				fmt.Fprintf(os.Stderr, "prepare panel MySQL database: %v\n", retryErr)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "prepare panel MySQL database: %v\n", err)
			os.Exit(1)
		}
	}

	if err := writeMySQLAdminDefaults(mysqlAdminDefaultsFile, adminConnection); err != nil {
		fmt.Fprintf(os.Stderr, "write MySQL admin defaults file: %v\n", err)
		os.Exit(1)
	}

	cfg := config.Config{
		AppName:           "Server Side Control",
		Environment:       "production",
		ListenAddr:        listenAddr,
		BaseURL:           baseURL,
		DatabaseDSN:       databaseDSN,
		BootstrapUser:     bootstrapUser,
		BootstrapPassword: bootstrapPassword,
		PAMService:        pamService,
		SessionCookieName: "ssc_session",
		MySQLAdminDefaultsFile: mysqlAdminDefaultsFile,
		NginxBinary:       nginxBinary,
		NginxAvailableDir: nginxAvailableDir,
		NginxEnabledDir:   nginxEnabledDir,
		CertbotBinary:     certbotBinary,
		HelperBinary:      helperBinary,
	}

	if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create config directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(envPath, []byte(cfg.ToEnv()), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write env file: %v\n", err)
		os.Exit(1)
	}

	if generatedDatabasePassword {
		fmt.Printf("\nGenerated panel MySQL password: %s\n", panelDatabasePassword)
	}

	fmt.Printf("\nConfig written to %s\n", envPath)
	fmt.Println("Next steps:")
	fmt.Println("1. Build the panel binary: go build -o build/server-side-control ./cmd/panel")
	fmt.Println("2. Install the systemd unit from deploy/systemd/server-side-control.service")
	fmt.Println("3. Start the service and open the base URL in your browser")
}

func prompt(reader *bufio.Reader, label string, fallback string, help string) string {
	printPromptHelp(help)
	fmt.Printf("%s [%s]: ", label, fallback)
	value, err := reader.ReadString('\n')
	if err != nil {
		return fallback
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}

	return trimmed
}

func promptPassword(reader *bufio.Reader, label string, fallback string, help string) string {
	printPromptHelp(help)
	if fallback == "" {
		fmt.Printf("%s: ", label)
	} else {
		fmt.Printf("%s [%s]: ", label, fallback)
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			trimmed := strings.TrimSpace(string(value))
			if trimmed == "" {
				return fallback
			}
			return trimmed
		}
	}

	value, err := reader.ReadString('\n')
	if err != nil {
		return fallback
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func printPromptHelp(help string) {
	if strings.TrimSpace(help) == "" {
		return
	}
	fmt.Printf("\n- %s\n", help)
}

func buildMySQLDSN(user string, password string, host string, port string, database string) string {
	cfg := mysql.Config{
		User:                 user,
		Passwd:               password,
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(host, port),
		DBName:               database,
		ParseTime:            true,
		AllowNativePasswords: true,
	}
	return cfg.FormatDSN()
}

type mysqlAdminConnection struct {
	User     string
	Password string
	Host     string
	Port     string
	Socket   string
}

func (c mysqlAdminConnection) DSN(database string) string {
	cfg := mysql.Config{
		User:                 c.User,
		Passwd:               c.Password,
		DBName:               database,
		ParseTime:            true,
		AllowNativePasswords: true,
	}
	if strings.TrimSpace(c.Socket) != "" {
		cfg.Net = "unix"
		cfg.Addr = c.Socket
	} else {
		cfg.Net = "tcp"
		cfg.Addr = net.JoinHostPort(c.Host, c.Port)
	}
	return cfg.FormatDSN()
}

func provisionPanelDatabase(adminDSN string, host string, port string, databaseName string, username string, password string) error {
	dataStore, err := store.Open(adminDSN)
	if err != nil {
		return err
	}
	defer dataStore.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := dataStore.ProvisionDatabase(ctx, databaseName, username, password); err != nil {
		return err
	}

	appStore, err := store.Open(buildMySQLDSN(username, password, host, port, databaseName))
	if err != nil {
		return err
	}
	defer appStore.Close()

	return appStore.Migrate(ctx)
}

func writeMySQLAdminDefaults(path string, connection mysqlAdminConnection) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	lines := []string{
		"[client]",
		fmt.Sprintf("user=%s", connection.User),
	}
	if strings.TrimSpace(connection.Password) != "" {
		lines = append(lines, fmt.Sprintf("password=%s", connection.Password))
	}
	if strings.TrimSpace(connection.Socket) != "" {
		lines = append(lines, fmt.Sprintf("socket=%s", connection.Socket))
	} else {
		lines = append(lines,
			fmt.Sprintf("host=%s", connection.Host),
			fmt.Sprintf("port=%s", connection.Port),
			"protocol=tcp",
		)
	}
	lines = append(lines, "")

	content := strings.Join(lines, "\n")

	return os.WriteFile(path, []byte(content), 0o600)
}

func fallbackToSocketAuth(connection mysqlAdminConnection, originalErr error) (mysqlAdminConnection, error) {
	if !isLocalMySQLHost(connection.Host) {
		return mysqlAdminConnection{}, originalErr
	}

	for _, socketPath := range []string{"/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock"} {
		if _, err := os.Stat(socketPath); err == nil {
			connection.Socket = socketPath
			return connection, nil
		}
	}

	return mysqlAdminConnection{}, originalErr
}

func isLocalMySQLHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	return host == "" || host == "127.0.0.1" || host == "localhost"
}

func randomPassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive")
	}

	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(buffer)
	if len(encoded) < length {
		return encoded, nil
	}
	return encoded[:length], nil
}
