package main

import (
	"errors"
	"encoding/json"
	"fmt"
	"io"
	"os"

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
	case "nginx.apply_site":
		var spec system.SiteSpec
		if err := json.Unmarshal(request.Input, &spec); err != nil {
			writeFailure(err, "")
			return
		}
		configPath, err := system.NewNginxManager(cfg.NginxAvailableDir, cfg.NginxEnabledDir, cfg.NginxBinary, cfg.CertbotBinary).ApplySite(spec)
		writeSuccess(map[string]string{"config_path": configPath}, "", err)
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
