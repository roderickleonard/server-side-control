package main

import (
	"errors"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/kaganyegin/server-side-control/internal/config"
	"github.com/kaganyegin/server-side-control/internal/system"
)

func main() {
	if os.Geteuid() != 0 {
		writeFailure(errors.New("helper must run as root"), "")
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

func handle(cfg config.Config, request system.HelperRequest) {
	switch request.Action {
	case "user.create":
		var input struct {
			Username   string `json:"username"`
			CreateHome bool   `json:"create_home"`
		}
		if err := json.Unmarshal(request.Input, &input); err != nil {
			writeFailure(err, "")
			return
		}
		err := system.NewUserManager().CreateLinuxUser(input.Username, input.CreateHome)
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
	case "runtime.inspect", "runtime.install_nvm", "runtime.install_node", "runtime.install_pm2", "runtime.start_pm2", "runtime.run_npm_script", "runtime.run_npm_install":
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
	default:
		writeFailure(fmt.Errorf("unknown helper action: %s", request.Action), "")
	}
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
