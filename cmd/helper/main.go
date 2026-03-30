package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kaganyegin/server-side-control/internal/config"
	"github.com/kaganyegin/server-side-control/internal/domain"
	"github.com/kaganyegin/server-side-control/internal/system"
)

func main() {
	if os.Geteuid() != 0 {
		writeFailure(errors.New("helper must run as root"), "")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "pty-terminal" {
		handlePTYMode(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "stream-runtime" || os.Args[1] == "stream-action") {
		handleStreamMode()
		return
	}
	cfg, err := config.Load()
	if err != nil {
		writeFailure(fmt.Errorf("load config: %w", err), "")
		return
	}

	var request system.HelperRequest
	if err := json.NewDecoder(io.LimitReader(os.Stdin, system.MaxHelperPayloadBytes)).Decode(&request); err != nil {
		writeFailure(fmt.Errorf("decode request: %w", err), "")
		return
	}
	if err := system.ValidateHelperAction(request.Action); err != nil {
		writeFailure(err, "")
		return
	}

	handle(cfg, request)
}

func handleStreamMode() {
	var request system.HelperRequest
	if err := json.NewDecoder(io.LimitReader(os.Stdin, system.MaxHelperPayloadBytes)).Decode(&request); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "decode request: %v\n", err)
		os.Exit(1)
	}
	if err := system.ValidateHelperAction(request.Action); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "validate request: %v\n", err)
		os.Exit(1)
	}
	switch request.Action {
	case "user.create":
		var input struct {
			Username   string `json:"username"`
			CreateHome bool   `json:"create_home"`
			Password   string `json:"password"`
			GrantSudo  bool   `json:"grant_sudo"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode user create spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamLinuxUserCreate(input.Username, input.CreateHome, input.Password, input.GrantSudo, os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "user.delete":
		var input struct {
			Username   string `json:"username"`
			RemoveHome bool   `json:"remove_home"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode user delete spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamLinuxUserDelete(input.Username, input.RemoveHome, os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "user.set_password":
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode user password spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamLinuxUserPassword(input.Username, input.Password, os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "user.set_sudo":
		var input struct {
			Username string `json:"username"`
			Enabled  bool   `json:"enabled"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode user sudo spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamLinuxUserSudo(input.Username, input.Enabled, os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "user.set_passwordless_sudo":
		var input struct {
			Username string `json:"username"`
			Enabled  bool   `json:"enabled"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode user passwordless sudo spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamLinuxUserPasswordlessSudo(input.Username, input.Enabled, os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "site.fix_laravel_permissions":
		var input struct {
			RootDir   string `json:"root_dir"`
			OwnerUser string `json:"owner_user"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode laravel permissions spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamFixLaravelPermissions(input.RootDir, input.OwnerUser, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "mysql.restore_database":
		var input struct {
			DatabaseName string `json:"database_name"`
			FilePath     string `json:"file_path"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode mysql restore spec: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Restoring database %s from %s\n\n", strings.TrimSpace(input.DatabaseName), strings.TrimSpace(input.FilePath))
		output, err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).RestoreDatabase(input.DatabaseName, input.FilePath)
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "panel.apply_proxy":
		var input system.PanelProxySpec
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode panel proxy spec: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Applying panel proxy for %s -> %s\n\n", strings.TrimSpace(input.Domain), strings.TrimSpace(input.ListenAddr))
		configPath, err := system.ApplyPanelProxy(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, input)
		if strings.TrimSpace(configPath) != "" {
			_, _ = fmt.Fprintf(os.Stdout, "Config path: %s\n", strings.TrimSpace(configPath))
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "panel.restart_service":
		serviceName := strings.TrimSpace(cfg.ServiceName)
		if serviceName == "" {
			serviceName = "server-side-control"
		}
		_, _ = fmt.Fprintf(os.Stdout, "Scheduling restart for %s\n\n", serviceName)
		cmd := exec.Command("bash", "-lc", fmt.Sprintf("nohup sh -c 'sleep 1; systemctl restart %s' >/dev/null 2>&1 &", serviceName))
		if output, err := cmd.CombinedOutput(); err != nil {
			trimmed := strings.TrimSpace(string(output))
			if trimmed != "" {
				_, _ = io.WriteString(os.Stderr, trimmed+"\n")
			}
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: restart panel service: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Restart scheduled for %s\n", serviceName)
	case "nginx.apply_site":
		var spec system.SiteSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode site spec: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Applying Nginx site %s for %s\n\n", strings.TrimSpace(spec.Name), strings.TrimSpace(spec.Domain))
		configPath, err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).ApplySite(spec)
		if strings.TrimSpace(configPath) != "" {
			_, _ = fmt.Fprintf(os.Stdout, "Config path: %s\n", strings.TrimSpace(configPath))
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "nginx.delete_site":
		var site system.SiteRemoval
		if err := json.Unmarshal(request.Input, &site); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode site removal spec: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Deleting Nginx site %s\n\n", strings.TrimSpace(site.Name))
		if err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).DeleteSite(site); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Deleted site %s\n", strings.TrimSpace(site.Name))
	case "nginx.enable_tls":
		var input system.TLSRequest
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode tls request: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Requesting TLS for %s\n\n", strings.TrimSpace(input.Domain))
		output, err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).EnableTLS(input)
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "deploy.rollback":
		var spec system.RollbackSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode rollback spec: %v\n", err)
			os.Exit(1)
		}
		result, err := system.NewDeployManager().Rollback(spec)
		if result.Output != "" {
			_, _ = io.WriteString(os.Stdout, result.Output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "pm2.list", "pm2.restart", "pm2.reload", "pm2.start", "pm2.stop", "pm2.logs":
		var input struct {
			User        string `json:"user"`
			ProcessName string `json:"process_name"`
			Lines       int    `json:"lines"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode pm2 spec: %v\n", err)
			os.Exit(1)
		}
		var (
			output string
			err error
		)
		switch request.Action {
		case "pm2.list":
			output, err = system.NewPM2Manager().List(input.User)
		case "pm2.restart":
			output, err = system.NewPM2Manager().Restart(input.User, input.ProcessName)
		case "pm2.reload":
			output, err = system.NewPM2Manager().Reload(input.User, input.ProcessName)
		case "pm2.start":
			output, err = system.NewPM2Manager().Start(input.User, input.ProcessName)
		case "pm2.stop":
			output, err = system.NewPM2Manager().Stop(input.User, input.ProcessName)
		default:
			output, err = system.NewPM2Manager().Logs(input.User, input.ProcessName, input.Lines)
		}
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "php.install_versions":
		var input struct {
			Versions []string `json:"versions"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode php install versions spec: %v\n", err)
			os.Exit(1)
		}
		output, err := system.NewPHPManager().InstallVersions(input.Versions)
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "php.install_extensions", "php.enable_extensions", "php.disable_extensions":
		var spec system.PHPExtensionSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode php extensions spec: %v\n", err)
			os.Exit(1)
		}
		var (
			output string
			err error
		)
		switch request.Action {
		case "php.install_extensions":
			output, err = system.NewPHPManager().InstallExtensions(spec)
		case "php.enable_extensions":
			output, err = system.NewPHPManager().EnableExtensions(spec)
		default:
			output, err = system.NewPHPManager().DisableExtensions(spec)
		}
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "php.update_ini_settings":
		var spec system.PHPINIUpdateSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode php ini spec: %v\n", err)
			os.Exit(1)
		}
		output, err := system.NewPHPManager().UpdateINISettings(spec)
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "php.switch":
		var input struct {
			ConfigPath string `json:"config_path"`
			Version    string `json:"version"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode php switch spec: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Switching %s to PHP %s\n", input.ConfigPath, input.Version)
		if err := system.NewPHPManager().SwitchSiteVersion(input.ConfigPath, input.Version); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "redis.install", "redis.start", "redis.stop", "redis.restart":
		var (
			output string
			err error
		)
		switch request.Action {
		case "redis.install":
			output, err = system.NewRedisManager().Install()
		case "redis.start":
			output, err = system.NewRedisManager().Start()
		case "redis.stop":
			output, err = system.NewRedisManager().Stop()
		default:
			output, err = system.NewRedisManager().Restart()
		}
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "redis.configure":
		var spec system.RedisConfigSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode redis config spec: %v\n", err)
			os.Exit(1)
		}
		output, err := system.NewRedisManager().Configure(spec)
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "redis.test_connection":
		var spec system.RedisPingSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode redis ping spec: %v\n", err)
			os.Exit(1)
		}
		output, err := system.NewRedisManager().TestConnection(spec)
		if output != "" {
			_, _ = io.WriteString(os.Stdout, output)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "deploy.run":
		var spec system.DeploySpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode deploy spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamDeploy(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "deploy.run_custom_git_command":
		var spec system.GitCommandSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode git command spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamGitCommand(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "runtime.run_npm_script":
		var spec system.NPMScriptSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode npm script spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamNPMScript(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "runtime.run_npm_install":
		var spec system.NPMInstallSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode npm install spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamNPMInstall(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "runtime.run_custom_command":
		var spec system.CustomRuntimeCommandSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode custom runtime command spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamCustomRuntimeCommand(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "runtime.install_composer":
		if err := system.StreamInstallComposer(os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "runtime.run_shell_command":
		var spec system.ShellCommandSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode shell command spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamShellCommand(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "git_auth.ensure_deploy_key":
		var spec system.GitDeployKeySpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode deploy key spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamEnsureDeployKey(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "git_auth.trust_host":
		var spec system.GitHostTrustSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode git host spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamTrustGitHost(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	case "git_auth.store_credential":
		var spec system.GitCredentialSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "decode git credential spec: %v\n", err)
			os.Exit(1)
		}
		if err := system.StreamStoreGitCredential(spec, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\ncommand failed: %v\n", err)
			os.Exit(1)
		}
	default:
		_, _ = fmt.Fprintf(os.Stderr, "stream action not supported: %s\n", request.Action)
		os.Exit(1)
	}
}

func handle(cfg config.Config, request system.HelperRequest) {
	switch request.Action {
	case "user.create":
		var input struct {
			Username   string `json:"username"`
			CreateHome bool   `json:"create_home"`
			Password   string `json:"password"`
			GrantSudo  bool   `json:"grant_sudo"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewUserManager().CreateLinuxUser(input.Username, input.CreateHome, input.Password, input.GrantSudo)
		writeSuccess(nil, "", err)
	case "user.list":
		users, err := system.NewUserManager().ListLinuxUsers()
		writeSuccess(users, "", err)
	case "user.delete":
		var input struct {
			Username   string `json:"username"`
			RemoveHome bool   `json:"remove_home"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewUserManager().DeleteLinuxUser(input.Username, input.RemoveHome)
		writeSuccess(nil, "", err)
	case "user.set_password":
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewUserManager().SetLinuxUserPassword(input.Username, input.Password)
		writeSuccess(nil, "", err)
	case "user.set_sudo":
		var input struct {
			Username string `json:"username"`
			Enabled  bool   `json:"enabled"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewUserManager().SetLinuxUserSudo(input.Username, input.Enabled)
		writeSuccess(nil, "", err)
	case "user.set_passwordless_sudo":
		var input struct {
			Username string `json:"username"`
			Enabled  bool   `json:"enabled"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewUserManager().SetLinuxUserPasswordlessSudo(input.Username, input.Enabled)
		writeSuccess(nil, "", err)
	case "mysql.provision_database":
		var input struct {
			DatabaseName     string `json:"database_name"`
			DatabaseUser     string `json:"database_user"`
			DatabasePassword string `json:"database_password"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).ProvisionDatabase(input.DatabaseName, input.DatabaseUser, input.DatabasePassword)
		writeSuccess(nil, "", err)
	case "mysql.list_access":
		entries, err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).ListDatabaseAccess()
		writeSuccess(entries, "", err)
	case "mysql.delete_access":
		var input struct {
			DatabaseName string `json:"database_name"`
			DatabaseUser string `json:"database_user"`
			DatabaseHost string `json:"database_host"`
			DropDatabase bool   `json:"drop_database"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).DeleteDatabaseAccess(input.DatabaseName, input.DatabaseUser, input.DatabaseHost, input.DropDatabase)
		writeSuccess(nil, "", err)
	case "mysql.rotate_user_password":
		var input struct {
			DatabaseUser     string `json:"database_user"`
			DatabaseHost     string `json:"database_host"`
			DatabasePassword string `json:"database_password"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).RotateUserPassword(input.DatabaseUser, input.DatabaseHost, input.DatabasePassword)
		writeSuccess(nil, "", err)
	case "mysql.rotate_admin_password":
		var input struct {
			Password string `json:"password"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).RotateAdminPassword(input.Password)
		writeSuccess(nil, "", err)
	case "mysql.inspect_database":
		var spec system.DatabaseInspectSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).InspectDatabase(spec)
		writeSuccess(result, "", err)
	case "mysql.restore_database":
		var input struct {
			DatabaseName string `json:"database_name"`
			FilePath     string `json:"file_path"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewDatabaseManager(cfg.MySQLAdminDefaultsFile).RestoreDatabase(input.DatabaseName, input.FilePath)
		writeSuccess(nil, output, err)
	case "panel.write_env":
		var input struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		if cfg.EnvPath == "" || !filepath.IsAbs(filepath.Clean(cfg.EnvPath)) {
			writeFailure(errors.New("invalid panel env path"), "")
			return
		}
		if err := os.MkdirAll(filepath.Dir(cfg.EnvPath), 0o755); err != nil {
			writeFailure(fmt.Errorf("create panel env directory: %w", err), "")
			return
		}
		if err := os.WriteFile(cfg.EnvPath, []byte(input.Content), 0o600); err != nil {
			writeFailure(fmt.Errorf("write panel env: %w", err), "")
			return
		}
		writeSuccess(nil, cfg.EnvPath, nil)
	case "panel.apply_proxy":
		var input system.PanelProxySpec
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		configPath, err := system.ApplyPanelProxy(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, input)
		writeSuccess(nil, configPath, err)
	case "panel.restart_service":
		serviceName := strings.TrimSpace(cfg.ServiceName)
		if serviceName == "" {
			serviceName = "server-side-control"
		}
		cmd := exec.Command("bash", "-lc", fmt.Sprintf("nohup sh -c 'sleep 1; systemctl restart %s' >/dev/null 2>&1 &", serviceName))
		if output, err := cmd.CombinedOutput(); err != nil {
			writeFailure(fmt.Errorf("restart panel service: %w: %s", err, strings.TrimSpace(string(output))), "")
			return
		}
		writeSuccess(nil, serviceName, nil)
	case "panel.inspect_tls":
		var input struct {
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		status := domain.PanelTLSStatus{Domain: strings.TrimSpace(input.Domain)}
		if status.Domain == "" {
			writeSuccess(status, "", nil)
			return
		}
		certPath := filepath.Join("/etc/letsencrypt/live", status.Domain, "fullchain.pem")
		content, err := os.ReadFile(certPath)
		if err != nil {
			writeSuccess(status, "", nil)
			return
		}
		block, _ := pem.Decode(content)
		if block == nil {
			writeSuccess(status, "", nil)
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			writeSuccess(status, "", nil)
			return
		}
		expiresAt := cert.NotAfter
		status.CertificateOK = true
		status.ExpiresAt = &expiresAt
		status.DaysRemaining = int(time.Until(expiresAt).Hours() / 24)
		status.Issuer = cert.Issuer.CommonName
		writeSuccess(status, "", nil)
	case "nginx.apply_site":
		var spec system.SiteSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		configPath, err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).ApplySite(spec)
		writeSuccess(map[string]string{"config_path": configPath}, "", err)
	case "nginx.delete_site":
		var site system.SiteRemoval
		if err := json.Unmarshal(request.Input, &site); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).DeleteSite(site)
		writeSuccess(nil, "", err)
	case "nginx.validate":
		var input struct{ Path string `json:"path"` }
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).ValidateConfig(input.Path)
		writeSuccess(nil, "", err)
	case "nginx.reload":
		err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).Reload()
		writeSuccess(nil, "", err)
	case "nginx.enable_tls":
		var input system.TLSRequest
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).EnableTLS(input)
		writeSuccess(nil, output, err)
	case "nginx.write_config":
		var input struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		cleanPath := filepath.Clean(input.Path)
		availableDir := filepath.Clean(cfg.NginxAvailableDir)
		if !filepath.IsAbs(cleanPath) {
			writeFailure(errors.New("nginx config path must be absolute"), "")
			return
		}
		if cleanPath != availableDir && !strings.HasPrefix(cleanPath, availableDir+string(os.PathSeparator)) {
			writeFailure(errors.New("nginx config path must be inside nginx available dir"), "")
			return
		}
		if err := os.WriteFile(cleanPath, []byte(input.Content), 0o644); err != nil {
			writeFailure(fmt.Errorf("write nginx config: %w", err), "")
			return
		}
		writeSuccess(nil, cleanPath, nil)
	case "nginx.validate_config":
		var input struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		cleanPath := filepath.Clean(input.Path)
		availableDir := filepath.Clean(cfg.NginxAvailableDir)
		if !filepath.IsAbs(cleanPath) {
			writeFailure(errors.New("nginx config path must be absolute"), "")
			return
		}
		if cleanPath != availableDir && !strings.HasPrefix(cleanPath, availableDir+string(os.PathSeparator)) {
			writeFailure(errors.New("nginx config path must be inside nginx available dir"), "")
			return
		}
		previousContent, err := os.ReadFile(cleanPath)
		if err != nil {
			writeFailure(fmt.Errorf("read current nginx config: %w", err), "")
			return
		}
		if err := os.WriteFile(cleanPath, []byte(input.Content), 0o644); err != nil {
			writeFailure(fmt.Errorf("write candidate nginx config: %w", err), "")
			return
		}
		validateErr := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).ValidateConfig(cleanPath)
		if restoreErr := os.WriteFile(cleanPath, previousContent, 0o644); restoreErr != nil {
			writeFailure(fmt.Errorf("restore nginx config after validate: %w", restoreErr), "")
			return
		}
		if validateErr != nil {
			writeFailure(validateErr, "")
			return
		}
		writeSuccess(nil, "nginx config validated successfully", nil)
	case "deploy.run":
		var spec system.DeploySpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := system.NewDeployManager().Deploy(spec)
		writeSuccess(result, result.Output, err)
	case "deploy.rollback":
		var spec system.RollbackSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := system.NewDeployManager().Rollback(spec)
		writeSuccess(result, result.Output, err)
	case "deploy.inspect":
		var spec system.RepositoryInspectSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := system.NewDeployManager().Inspect(spec)
		writeSuccess(result, "", err)
	case "runtime.inspect", "runtime.install_nvm", "runtime.install_node", "runtime.install_pm2", "runtime.install_composer", "runtime.start_pm2", "runtime.run_npm_script", "runtime.run_npm_install":
		handleRuntime(request)
	case "git_auth.inspect", "git_auth.ensure_deploy_key", "git_auth.trust_host", "git_auth.store_credential":
		handleGitAuth(request)
	case "pm2.list", "pm2.restart", "pm2.reload", "pm2.start", "pm2.stop", "pm2.logs":
		handlePM2(request)
	case "php.switch":
		var input struct {
			ConfigPath string `json:"config_path"`
			Version    string `json:"version"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewPHPManager().SwitchSiteVersion(input.ConfigPath, input.Version)
		writeSuccess(nil, "", err)
	case "php.list_versions":
		versions, err := system.NewPHPManager().ListAvailableVersions()
		writeSuccess(versions, "", err)
	case "php.list_installable_versions":
		versions, err := system.NewPHPManager().ListInstallableVersions()
		writeSuccess(versions, "", err)
	case "php.install_versions":
		var input struct {
			Versions []string `json:"versions"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewPHPManager().InstallVersions(input.Versions)
		writeSuccess(nil, output, err)
	case "php.list_extension_status":
		var input struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		status, err := system.NewPHPManager().ListExtensionStatus(input.Version)
		writeSuccess(status, "", err)
	case "php.install_extensions":
		var spec system.PHPExtensionSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewPHPManager().InstallExtensions(spec)
		writeSuccess(nil, output, err)
	case "php.enable_extensions":
		var spec system.PHPExtensionSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewPHPManager().EnableExtensions(spec)
		writeSuccess(nil, output, err)
	case "php.disable_extensions":
		var spec system.PHPExtensionSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewPHPManager().DisableExtensions(spec)
		writeSuccess(nil, output, err)
	case "php.diagnostics":
		var input struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := system.NewPHPManager().Diagnostics(input.Version)
		writeSuccess(result, "", err)
	case "php.read_ini_settings":
		var input struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := system.NewPHPManager().ReadINISettings(input.Version)
		writeSuccess(result, "", err)
	case "php.update_ini_settings":
		var spec system.PHPINIUpdateSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewPHPManager().UpdateINISettings(spec)
		writeSuccess(nil, output, err)
	case "redis.inspect":
		status, err := system.NewRedisManager().Inspect()
		writeSuccess(status, "", err)
	case "redis.install":
		output, err := system.NewRedisManager().Install()
		writeSuccess(nil, output, err)
	case "redis.configure":
		var spec system.RedisConfigSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewRedisManager().Configure(spec)
		writeSuccess(nil, output, err)
	case "redis.start":
		output, err := system.NewRedisManager().Start()
		writeSuccess(nil, output, err)
	case "redis.stop":
		output, err := system.NewRedisManager().Stop()
		writeSuccess(nil, output, err)
	case "redis.restart":
		output, err := system.NewRedisManager().Restart()
		writeSuccess(nil, output, err)
	case "redis.test_connection":
		var spec system.RedisPingSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewRedisManager().TestConnection(spec)
		writeSuccess(nil, output, err)
	case "redis.logs":
		var input struct {
			Lines int `json:"lines"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.NewRedisManager().Logs(input.Lines)
		writeSuccess(nil, output, err)
	case "cron.list":
		var input struct {
			User string `json:"user"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		jobs, err := system.ListCronJobs(input.User)
		writeSuccess(jobs, "", err)
	case "cron.create":
		var spec system.CronJobSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.CreateCronJob(spec)
		writeSuccess(nil, output, err)
	case "cron.update":
		var spec system.CronJobUpdateSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.UpdateCronJob(spec)
		writeSuccess(nil, output, err)
	case "cron.delete":
		var spec system.CronJobDeleteSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.DeleteCronJob(spec)
		writeSuccess(nil, output, err)
	case "cron.clear_log":
		var input struct {
			User string `json:"user"`
			ID   string `json:"id"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.ClearCronJobLog(input.User, input.ID)
		writeSuccess(nil, output, err)
	case "cron.rotate_log":
		var input struct {
			User string `json:"user"`
			ID   string `json:"id"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := system.RotateCronJobLog(input.User, input.ID)
		writeSuccess(nil, output, err)
	case "files.write_env":
		var input struct {
			Path    string `json:"path"`
			Content string `json:"content"`
			Owner   string `json:"owner"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		cleanPath := filepath.Clean(input.Path)
		if !filepath.IsAbs(cleanPath) || filepath.Base(cleanPath) != ".env" {
			writeFailure(errors.New("invalid env file path: must be absolute and end with /.env"), "")
			return
		}
		ownerPat := regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
		if !ownerPat.MatchString(input.Owner) {
			writeFailure(errors.New("invalid owner username"), "")
			return
		}
		u, err := user.Lookup(input.Owner)
		if err != nil {
			writeFailure(fmt.Errorf("user not found: %w", err), "")
			return
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		if err := os.WriteFile(cleanPath, []byte(input.Content), 0o600); err != nil {
			writeFailure(fmt.Errorf("write env file: %w", err), "")
			return
		}
		if err := os.Chown(cleanPath, uid, gid); err != nil {
			writeFailure(fmt.Errorf("chown env file: %w", err), "")
			return
		}
		writeSuccess(nil, "", nil)
	case "files.read_env":
		var input struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		cleanPath := filepath.Clean(input.Path)
		if !filepath.IsAbs(cleanPath) || filepath.Base(cleanPath) != ".env" {
			writeFailure(errors.New("invalid env file path"), "")
			return
		}
		content, err := os.ReadFile(cleanPath)
		if err != nil {
			// file doesn't exist yet — return empty, not an error
			writeSuccess("", "", nil)
			return
		}
		writeSuccess(string(content), "", nil)
	case "files.read_text":
		var input struct {
			Path     string `json:"path"`
			MaxBytes int    `json:"max_bytes"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		cleanPath := filepath.Clean(input.Path)
		if !filepath.IsAbs(cleanPath) {
			writeFailure(errors.New("path must be absolute"), "")
			return
		}
		content, err := readTextFile(cleanPath, input.MaxBytes)
		if err != nil {
			writeSuccess("", "", nil)
			return
		}
		writeSuccess(content, "", nil)
	case "files.list_dir":
		var input struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		cleanPath := filepath.Clean(input.Path)
		if !filepath.IsAbs(cleanPath) {
			writeFailure(errors.New("path must be absolute"), "")
			return
		}
		entries, err := os.ReadDir(cleanPath)
		if err != nil {
			writeFailure(err, "")
			return
		}
		type dirEntry struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
			Size  int64  `json:"size"`
		}
		items := make([]dirEntry, 0, len(entries))
		for _, entry := range entries {
			info, infoErr := entry.Info()
			size := int64(0)
			if infoErr == nil {
				size = info.Size()
			}
			items = append(items, dirEntry{Name: entry.Name(), IsDir: entry.IsDir(), Size: size})
		}
		writeSuccess(items, "", nil)
	default:
		writeFailure(fmt.Errorf("unknown helper action: %s", request.Action), "")
	}
}

func readTextFile(path string, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(content), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	buffer, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return "", err
	}
	if len(buffer) <= maxBytes {
		return string(buffer), nil
	}
	return string(buffer[:maxBytes]) + fmt.Sprintf("\n\n[truncated after %d bytes]", maxBytes), nil
}

func handlePM2(request system.HelperRequest) {
	var input struct {
		User        string `json:"user"`
		ProcessName string `json:"process_name"`
		Lines       int    `json:"lines"`
	}
	if err := json.Unmarshal(request.Input, &input); err != nil {
		writeFailure(err, "")
		return
	}
	manager := system.NewPM2Manager()
	var (
		output string
		err    error
	)
	switch request.Action {
	case "pm2.list":
		output, err = manager.List(input.User)
	case "pm2.restart":
		output, err = manager.Restart(input.User, input.ProcessName)
	case "pm2.reload":
		output, err = manager.Reload(input.User, input.ProcessName)
	case "pm2.start":
		output, err = manager.Start(input.User, input.ProcessName)
	case "pm2.stop":
		output, err = manager.Stop(input.User, input.ProcessName)
	case "pm2.logs":
		output, err = manager.Logs(input.User, input.ProcessName, input.Lines)
	}
	writeSuccess(nil, output, err)
}

func handleRuntime(request system.HelperRequest) {
	manager := system.NewRuntimeManager()
	switch request.Action {
	case "runtime.inspect":
		var spec system.RuntimeInspectSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := manager.Inspect(spec)
		writeSuccess(result, "", err)
	case "runtime.install_nvm":
		var input struct{ User string `json:"user"` }
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.InstallNVM(input.User)
		writeSuccess(nil, output, err)
	case "runtime.install_node":
		var spec system.NodeInstallSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.InstallNode(spec)
		writeSuccess(nil, output, err)
	case "runtime.install_pm2":
		var spec system.PM2InstallSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.InstallPM2(spec)
		writeSuccess(nil, output, err)
	case "runtime.install_composer":
		output, err := manager.InstallComposer()
		writeSuccess(nil, output, err)
	case "runtime.start_pm2":
		var spec system.PM2StartSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.StartPM2(spec)
		writeSuccess(nil, output, err)
	case "runtime.run_npm_script":
		var spec system.NPMScriptSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.RunNPMScript(spec)
		writeSuccess(nil, output, err)
	case "runtime.run_npm_install":
		var spec system.NPMInstallSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.RunNPMInstall(spec)
		writeSuccess(nil, output, err)
	default:
		writeFailure(fmt.Errorf("unknown runtime action: %s", request.Action), "")
	}
}

func handleGitAuth(request system.HelperRequest) {
	manager := system.NewGitAuthManager()
	switch request.Action {
	case "git_auth.inspect":
		var spec system.GitAuthInspectSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		result, err := manager.Inspect(spec)
		writeSuccess(result, "", err)
	case "git_auth.ensure_deploy_key":
		var spec system.GitDeployKeySpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		result, output, err := manager.EnsureDeployKey(spec)
		writeSuccess(result, output, err)
	case "git_auth.trust_host":
		var spec system.GitHostTrustSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.TrustHost(spec)
		writeSuccess(nil, output, err)
	case "git_auth.store_credential":
		var spec system.GitCredentialSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		output, err := manager.StoreCredential(spec)
		writeSuccess(nil, output, err)
	default:
		writeFailure(fmt.Errorf("unknown git auth action: %s", request.Action), "")
	}
}

func writeSuccess(data any, output string, err error) {
	if err != nil {
		writeFailure(err, output)
		return
	}
	var encoded json.RawMessage
	if data != nil {
		payload, marshalErr := json.Marshal(data)
		if marshalErr != nil {
			writeFailure(marshalErr, output)
			return
		}
		encoded = payload
	}
	_ = json.NewEncoder(os.Stdout).Encode(system.HelperResponse{OK: true, Output: output, Data: encoded})
}

func writeFailure(err error, output string) {
	_ = json.NewEncoder(os.Stdout).Encode(system.HelperResponse{OK: false, Error: err.Error(), Output: output})
}
