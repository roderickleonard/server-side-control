package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

type HelperRequest struct {
	Action string          `json:"action"`
	Input  json.RawMessage `json:"input,omitempty"`
}

type HelperResponse struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Output string          `json:"output,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type HelperClient struct {
	helperBinary string
}

func NewHelperClient(helperBinary string) *HelperClient {
	if helperBinary == "" {
		helperBinary = "/usr/local/bin/server-side-control-helper"
	}
	return &HelperClient{helperBinary: helperBinary}
}

func (c *HelperClient) Call(ctx context.Context, action string, input any, output any) (string, error) {
	if !filepath.IsAbs(c.helperBinary) {
		return "", fmt.Errorf("helper binary path must be absolute")
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	requestPayload, err := json.Marshal(HelperRequest{Action: action, Input: payload})
	if err != nil {
		return "", err
	}

	callCtx := ctx
	if callCtx == nil {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(callCtx, "sudo", "-n", c.helperBinary)
	cmd.Stdin = bytes.NewReader(requestPayload)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return stderr.String(), fmt.Errorf("helper command failed: %w: %s", err, stderr.String())
		}
		return stdout.String(), fmt.Errorf("helper command failed: %w", err)
	}

	var response HelperResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return stdout.String(), fmt.Errorf("decode helper response: %w", err)
	}
	if !response.OK {
		return response.Output, fmt.Errorf(response.Error)
	}
	if output != nil && len(response.Data) > 0 {
		if err := json.Unmarshal(response.Data, output); err != nil {
			return response.Output, fmt.Errorf("decode helper data: %w", err)
		}
	}
	return response.Output, nil
}

type helperUserManager struct{ client *HelperClient }

type helperDatabaseManager struct{ client *HelperClient }

type helperNginxManager struct{ client *HelperClient }

type helperDeployManager struct{ client *HelperClient }

type helperRuntimeManager struct{ client *HelperClient }

type helperGitAuthManager struct{ client *HelperClient }

type helperPM2Manager struct{ client *HelperClient }

type helperPHPManager struct{ client *HelperClient }

func NewHelperUserManager(client *HelperClient) UserManager {
	return &helperUserManager{client: client}
}

func NewHelperDatabaseManager(client *HelperClient) DatabaseManager {
	return &helperDatabaseManager{client: client}
}

func NewHelperNginxManager(client *HelperClient) NginxManager {
	return &helperNginxManager{client: client}
}

func NewHelperDeployManager(client *HelperClient) DeployManager {
	return &helperDeployManager{client: client}
}

func NewHelperRuntimeManager(client *HelperClient) RuntimeManager {
	return &helperRuntimeManager{client: client}
}

func NewHelperGitAuthManager(client *HelperClient) GitAuthManager {
	return &helperGitAuthManager{client: client}
}

func NewHelperPM2Manager(client *HelperClient) PM2Manager {
	return &helperPM2Manager{client: client}
}

func NewHelperPHPManager(client *HelperClient) PHPManager {
	return &helperPHPManager{client: client}
}

func (m *helperUserManager) CreateLinuxUser(username string, createHome bool) error {
	_, err := m.client.Call(context.Background(), "user.create", map[string]any{
		"username":    username,
		"create_home": createHome,
	}, nil)
	return err
}

func (m *helperUserManager) ListLinuxUsers() ([]LinuxUser, error) {
	var users []LinuxUser
	_, err := m.client.Call(context.Background(), "user.list", map[string]any{}, &users)
	return users, err
}

func (m *helperUserManager) DeleteLinuxUser(username string, removeHome bool) error {
	_, err := m.client.Call(context.Background(), "user.delete", map[string]any{
		"username":    username,
		"remove_home": removeHome,
	}, nil)
	return err
}

func (m *helperDatabaseManager) ProvisionDatabase(name string, username string, password string) error {
	_, err := m.client.Call(context.Background(), "mysql.provision_database", map[string]any{
		"database_name": name,
		"database_user": username,
		"database_password": password,
	}, nil)
	return err
}

func (m *helperDatabaseManager) ListDatabaseAccess() ([]DatabaseAccess, error) {
	var entries []DatabaseAccess
	_, err := m.client.Call(context.Background(), "mysql.list_access", map[string]any{}, &entries)
	return entries, err
}

func (m *helperDatabaseManager) DeleteDatabaseAccess(name string, username string, host string, dropDatabase bool) error {
	_, err := m.client.Call(context.Background(), "mysql.delete_access", map[string]any{
		"database_name": name,
		"database_user": username,
		"database_host": host,
		"drop_database": dropDatabase,
	}, nil)
	return err
}

func (m *helperDatabaseManager) RotateUserPassword(username string, host string, password string) error {
	_, err := m.client.Call(context.Background(), "mysql.rotate_user_password", map[string]any{
		"database_user": username,
		"database_host": host,
		"database_password": password,
	}, nil)
	return err
}

func (m *helperDatabaseManager) RotateAdminPassword(password string) error {
	_, err := m.client.Call(context.Background(), "mysql.rotate_admin_password", map[string]any{
		"password": password,
	}, nil)
	return err
}

func (m *helperDatabaseManager) InspectDatabase(spec DatabaseInspectSpec) (DatabaseDetails, error) {
	var details DatabaseDetails
	_, err := m.client.Call(context.Background(), "mysql.inspect_database", spec, &details)
	return details, err
}

func (m *helperDatabaseManager) RestoreDatabase(name string, filePath string) (string, error) {
	return m.client.Call(context.Background(), "mysql.restore_database", map[string]any{
		"database_name": name,
		"file_path":     filePath,
	}, nil)
}

func (m *helperNginxManager) ApplySite(spec SiteSpec) (string, error) {
	var data struct {
		ConfigPath string `json:"config_path"`
	}
	output, err := m.client.Call(context.Background(), "nginx.apply_site", spec, &data)
	if err != nil {
		if output != "" {
			return "", fmt.Errorf("%w: %s", err, output)
		}
		return "", err
	}
	return data.ConfigPath, nil
}

func (m *helperNginxManager) DeleteSite(site SiteRemoval) error {
	_, err := m.client.Call(context.Background(), "nginx.delete_site", site, nil)
	return err
}

func (m *helperNginxManager) ValidateConfig(path string) error {
	_, err := m.client.Call(context.Background(), "nginx.validate", map[string]any{"path": path}, nil)
	return err
}

func (m *helperNginxManager) Reload() error {
	_, err := m.client.Call(context.Background(), "nginx.reload", map[string]any{}, nil)
	return err
}

func (m *helperNginxManager) EnableTLS(request TLSRequest) (string, error) {
	return m.client.Call(context.Background(), "nginx.enable_tls", request, nil)
}

func (m *helperDeployManager) Deploy(spec DeploySpec) (DeployResult, error) {
	var result DeployResult
	output, err := m.client.Call(context.Background(), "deploy.run", spec, &result)
	if err != nil {
		result.Output = output
		return result, err
	}
	return result, nil
}

func (m *helperDeployManager) Rollback(spec RollbackSpec) (DeployResult, error) {
	var result DeployResult
	output, err := m.client.Call(context.Background(), "deploy.rollback", spec, &result)
	if err != nil {
		result.Output = output
		return result, err
	}
	return result, nil
}

func (m *helperDeployManager) Inspect(spec RepositoryInspectSpec) (RepositoryStatus, error) {
	var result RepositoryStatus
	_, err := m.client.Call(context.Background(), "deploy.inspect", spec, &result)
	return result, err
}

func (m *helperRuntimeManager) Inspect(spec RuntimeInspectSpec) (RuntimeStatus, error) {
	var result RuntimeStatus
	_, err := m.client.Call(context.Background(), "runtime.inspect", spec, &result)
	return result, err
}

func (m *helperRuntimeManager) InstallNVM(user string) (string, error) {
	return m.client.Call(context.Background(), "runtime.install_nvm", map[string]any{"user": user}, nil)
}

func (m *helperRuntimeManager) InstallNode(spec NodeInstallSpec) (string, error) {
	return m.client.Call(context.Background(), "runtime.install_node", spec, nil)
}

func (m *helperRuntimeManager) InstallPM2(spec PM2InstallSpec) (string, error) {
	return m.client.Call(context.Background(), "runtime.install_pm2", spec, nil)
}

func (m *helperRuntimeManager) StartPM2(spec PM2StartSpec) (string, error) {
	return m.client.Call(context.Background(), "runtime.start_pm2", spec, nil)
}

func (m *helperGitAuthManager) Inspect(spec GitAuthInspectSpec) (GitAuthStatus, error) {
	var result GitAuthStatus
	_, err := m.client.Call(context.Background(), "git_auth.inspect", spec, &result)
	return result, err
}

func (m *helperGitAuthManager) EnsureDeployKey(spec GitDeployKeySpec) (GitAuthStatus, string, error) {
	var result GitAuthStatus
	output, err := m.client.Call(context.Background(), "git_auth.ensure_deploy_key", spec, &result)
	return result, output, err
}

func (m *helperGitAuthManager) TrustHost(spec GitHostTrustSpec) (string, error) {
	return m.client.Call(context.Background(), "git_auth.trust_host", spec, nil)
}

func (m *helperGitAuthManager) StoreCredential(spec GitCredentialSpec) (string, error) {
	return m.client.Call(context.Background(), "git_auth.store_credential", spec, nil)
}

func (m *helperPM2Manager) List(user string) (string, error) {
	return m.call("pm2.list", user, "", 0)
}

func (m *helperPM2Manager) Restart(user string, processName string) (string, error) {
	return m.call("pm2.restart", user, processName, 0)
}

func (m *helperPM2Manager) Reload(user string, processName string) (string, error) {
	return m.call("pm2.reload", user, processName, 0)
}

func (m *helperPM2Manager) Start(user string, processName string) (string, error) {
	return m.call("pm2.start", user, processName, 0)
}

func (m *helperPM2Manager) Stop(user string, processName string) (string, error) {
	return m.call("pm2.stop", user, processName, 0)
}

func (m *helperPM2Manager) Logs(user string, processName string, lines int) (string, error) {
	return m.call("pm2.logs", user, processName, lines)
}

func (m *helperPM2Manager) call(action string, user string, processName string, lines int) (string, error) {
	output, err := m.client.Call(context.Background(), action, map[string]any{
		"user":         user,
		"process_name": processName,
		"lines":        lines,
	}, nil)
	return output, err
}

func (m *helperPHPManager) SwitchSiteVersion(configPath string, version string) error {
	_, err := m.client.Call(context.Background(), "php.switch", map[string]any{
		"config_path": configPath,
		"version":     version,
	}, nil)
	return err
}

func (m *helperPHPManager) ListAvailableVersions() ([]string, error) {
	var versions []string
	_, err := m.client.Call(context.Background(), "php.list_versions", map[string]any{}, &versions)
	return versions, err
}
