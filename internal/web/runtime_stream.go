package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/kaganyegin/server-side-control/internal/domain"
	"github.com/kaganyegin/server-side-control/internal/system"
)

type flushWriter struct {
	mu      sync.Mutex
	writer  http.ResponseWriter
	flusher http.Flusher
}

func (a *App) streamHelperAction(ctx context.Context, streamWriter io.Writer, action string, payload any) error {
	requestPayload, err := json.Marshal(system.HelperRequest{Action: action, Input: mustMarshal(payload)})
	if err != nil {
		return fmt.Errorf("encode helper request: %w", err)
	}
	cmd := exec.CommandContext(ctx, "sudo", "-n", a.cfg.HelperBinary, "stream-action")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("open helper stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open helper stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("open helper stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start helper: %w", err)
	}
	go func() {
		_, _ = stdin.Write(requestPayload)
		_ = stdin.Close()
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(streamWriter, stdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(streamWriter, stderr)
	}()
	err = cmd.Wait()
	wg.Wait()
	if err != nil {
		return err
	}
	return nil
}

func (w *flushWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.writer.Write(p)
	if err == nil {
		w.flusher.Flush()
	}
	return n, err
}

func (a *App) handleSiteRuntimeStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	siteName := strings.TrimSpace(r.FormValue("site_name"))
	if siteName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "site name is required"})
		return
	}
	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "managed site could not be found"})
		return
	}
	action := strings.TrimSpace(r.FormValue("details_action"))
	targetDirectory := site.RootDirectory
	targetLabel := site.Name
	if subdomainID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64); err == nil && subdomainID > 0 {
		if subdomains, listErr := a.store.ListSiteSubdomains(r.Context(), site.ID); listErr == nil {
			if subdomain, ok := findSiteSubdomain(subdomains, subdomainID); ok {
				targetDirectory = subdomain.RootDirectory
				targetLabel = subdomain.FullDomain
			}
		}
	}
	var (
		helperAction string
		payload      any
		auditAction  string
		label        string
	)
	switch action {
	case "install_composer":
		helperAction = "runtime.install_composer"
		payload = map[string]any{}
		auditAction = "runtime.install_composer"
		label = "install composer"
	case "npm_install":
		nodeVersion := strings.TrimSpace(r.FormValue("npm_script_node_version"))
		ci := r.FormValue("npm_ci") == "1"
		helperAction = "runtime.run_npm_install"
		payload = system.NPMInstallSpec{
			User:             site.OwnerLinuxUser,
			WorkingDirectory: targetDirectory,
			NodeVersion:      nodeVersion,
			CI:               ci,
		}
		auditAction = "runtime.npm_install"
		label = "npm install"
		if ci {
			label = "npm ci"
		}
	case "run_npm_script":
		nodeVersion := strings.TrimSpace(r.FormValue("npm_script_node_version"))
		scriptName := strings.TrimSpace(r.FormValue("script_name"))
		if scriptName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "script name is required"})
			return
		}
		helperAction = "runtime.run_npm_script"
		payload = system.NPMScriptSpec{
			User:             site.OwnerLinuxUser,
			WorkingDirectory: targetDirectory,
			ScriptName:       scriptName,
			NodeVersion:      nodeVersion,
		}
		auditAction = "runtime.run_npm_script"
		label = "npm run " + scriptName
	case "run_custom_command":
		commandBody := strings.TrimSpace(r.FormValue("runtime_command_body"))
		if commandBody == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "custom command is required"})
			return
		}
		helperAction = "runtime.run_custom_command"
		payload = system.CustomRuntimeCommandSpec{
			User:             site.OwnerLinuxUser,
			WorkingDirectory: targetDirectory,
			CommandBody:      commandBody,
			NodeVersion:      strings.TrimSpace(r.FormValue("runtime_command_node_version")),
		}
		auditAction = "runtime.run_custom_command"
		label = firstNonEmpty(strings.TrimSpace(r.FormValue("runtime_command_name")), "custom script")
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported runtime action"})
		return
	}

	requestPayload, err := json.Marshal(system.HelperRequest{Action: helperAction, Input: mustMarshal(payload)})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encode helper request"})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return
	}
	streamWriter := &flushWriter{writer: w, flusher: flusher}
	_, _ = io.WriteString(streamWriter, "$ "+label+"\n\n")

	cmd := exec.CommandContext(r.Context(), "sudo", "-n", a.cfg.HelperBinary, "stream-runtime")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stdin: %v\n", err))
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stdout: %v\n", err))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stderr: %v\n", err))
		return
	}
	if err := cmd.Start(); err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not start helper: %v\n", err))
		return
	}
	go func() {
		_, _ = stdin.Write(requestPayload)
		_ = stdin.Close()
	}()

	var output bytes.Buffer
	multiOut := io.MultiWriter(streamWriter, &output)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(multiOut, stdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(multiOut, stderr)
	}()
	err = cmd.Wait()
	wg.Wait()
	if err != nil {
		a.recordAudit(r.Context(), auditAction, targetLabel, "failure", map[string]any{"label": label, "error": err.Error()})
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	a.recordAudit(r.Context(), auditAction, targetLabel, "success", map[string]any{"label": label})
	_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
}

func (a *App) handleUsersStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	action := strings.TrimSpace(r.FormValue("user_action"))
	var (
		helperAction string
		payload      any
		auditAction  string
		target       string
		label        string
		auditMeta    map[string]any
		postCreatePasswordless bool
	)
	switch action {
	case "create":
		username := strings.TrimSpace(r.FormValue("username"))
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
			return
		}
		createHome := r.FormValue("create_home") == "1"
		grantSudo := r.FormValue("grant_sudo") == "1"
		postCreatePasswordless = r.FormValue("grant_passwordless_sudo") == "1"
		payload = map[string]any{
			"username":    username,
			"create_home": createHome,
			"password":    r.FormValue("linux_password"),
			"grant_sudo":  grantSudo,
		}
		helperAction = "user.create"
		auditAction = "user.create"
		target = username
		label = "create linux user"
		auditMeta = map[string]any{"create_home": createHome, "grant_sudo": grantSudo, "grant_passwordless_sudo": postCreatePasswordless}
	case "delete":
		username := strings.TrimSpace(r.FormValue("delete_username"))
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
			return
		}
		removeHome := r.FormValue("remove_home") == "1"
		payload = map[string]any{"username": username, "remove_home": removeHome}
		helperAction = "user.delete"
		auditAction = "user.delete"
		target = username
		label = "delete linux user"
		auditMeta = map[string]any{"remove_home": removeHome}
	case "set_password":
		username := strings.TrimSpace(r.FormValue("password_username"))
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
			return
		}
		password := r.FormValue("set_linux_password")
		if password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required"})
			return
		}
		payload = map[string]any{"username": username, "password": password}
		helperAction = "user.set_password"
		auditAction = "user.set_password"
		target = username
		label = "set linux password"
	case "set_sudo":
		username := strings.TrimSpace(r.FormValue("sudo_username"))
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
			return
		}
		enabled := r.FormValue("sudo_enabled") == "1"
		payload = map[string]any{"username": username, "enabled": enabled}
		helperAction = "user.set_sudo"
		auditAction = "user.set_sudo"
		target = username
		label = "update sudo access"
		auditMeta = map[string]any{"enabled": enabled}
	case "set_passwordless_sudo":
		username := strings.TrimSpace(r.FormValue("passwordless_sudo_username"))
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
			return
		}
		enabled := r.FormValue("passwordless_sudo_enabled") == "1"
		payload = map[string]any{"username": username, "enabled": enabled}
		helperAction = "user.set_passwordless_sudo"
		auditAction = "user.set_passwordless_sudo"
		target = username
		label = "update passwordless sudo"
		auditMeta = map[string]any{"enabled": enabled}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported user action"})
		return
	}

	requestPayload, err := json.Marshal(system.HelperRequest{Action: helperAction, Input: mustMarshal(payload)})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encode helper request"})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return
	}
	streamWriter := &flushWriter{writer: w, flusher: flusher}
	_, _ = io.WriteString(streamWriter, "$ "+label+"\n\n")

	cmd := exec.CommandContext(r.Context(), "sudo", "-n", a.cfg.HelperBinary, "stream-action")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stdin: %v\n", err))
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stdout: %v\n", err))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stderr: %v\n", err))
		return
	}
	if err := cmd.Start(); err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not start helper: %v\n", err))
		return
	}
	go func() {
		_, _ = stdin.Write(requestPayload)
		_ = stdin.Close()
	}()

	var output bytes.Buffer
	multiOut := io.MultiWriter(streamWriter, &output)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(multiOut, stdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(multiOut, stderr)
	}()
	err = cmd.Wait()
	wg.Wait()
	if err != nil {
		failureMeta := map[string]any{"error": err.Error()}
		for key, value := range auditMeta {
			failureMeta[key] = value
		}
		a.recordAudit(r.Context(), auditAction, target, "failure", failureMeta)
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	if action == "create" && postCreatePasswordless {
		_, _ = io.WriteString(streamWriter, "\n\n$ update passwordless sudo\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "user.set_passwordless_sudo", map[string]any{"username": target, "enabled": true}); err != nil {
			failureMeta := map[string]any{"error": err.Error(), "stage": "passwordless_sudo"}
			for key, value := range auditMeta {
				failureMeta[key] = value
			}
			a.recordAudit(r.Context(), "user.set_passwordless_sudo", target, "failure", failureMeta)
			_, _ = io.WriteString(streamWriter, "\n\n[user created, but NOPASSWD setup failed]\n")
			return
		}
		a.recordAudit(r.Context(), "user.set_passwordless_sudo", target, "success", map[string]any{"enabled": true})
	}
	a.recordAudit(r.Context(), auditAction, target, "success", auditMeta)
	_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
}

func (a *App) handlePHPStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	action := firstNonEmpty(strings.TrimSpace(r.FormValue("php_action")), "switch_version")
	selectedExtensions := collectPHPExtensions(r)
	var (
		helperAction string
		payload      any
		auditAction  string
		target       string
		label        string
		auditMeta    map[string]any
		afterSuccess func() error
	)
	switch action {
	case "install_versions":
		versions := append([]string{}, r.Form["install_versions"]...)
		if len(versions) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "select at least one PHP version"})
			return
		}
		helperAction = "php.install_versions"
		payload = map[string]any{"versions": versions}
		auditAction = "php.install_versions"
		target = strings.Join(versions, ",")
		label = "install php versions"
		auditMeta = map[string]any{"versions": versions}
	case "install_extensions", "enable_extensions", "disable_extensions":
		version := strings.TrimSpace(r.FormValue("extension_version"))
		if version == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "php version is required"})
			return
		}
		if len(selectedExtensions) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "select or enter at least one extension"})
			return
		}
		spec := system.PHPExtensionSpec{Version: version, Extensions: selectedExtensions}
		helperAction = "php." + action
		payload = spec
		auditAction = "php." + action
		target = version
		label = strings.ReplaceAll(action, "_", " ")
		auditMeta = map[string]any{"extensions": selectedExtensions}
	case "update_ini":
		version := strings.TrimSpace(r.FormValue("ini_version"))
		if version == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "php version is required"})
			return
		}
		helperAction = "php.update_ini_settings"
		payload = system.PHPINIUpdateSpec{
			Version:           version,
			MemoryLimit:       strings.TrimSpace(r.FormValue("memory_limit")),
			UploadMaxFilesize: strings.TrimSpace(r.FormValue("upload_max_filesize")),
			PostMaxSize:       strings.TrimSpace(r.FormValue("post_max_size")),
			MaxExecutionTime:  strings.TrimSpace(r.FormValue("max_execution_time")),
		}
		auditAction = "php.update_ini"
		target = version
		label = "update php ini"
	case "switch_version":
		if a.store == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "managed site storage is not configured"})
			return
		}
		siteName := strings.TrimSpace(r.FormValue("site_name"))
		phpVersion := strings.TrimSpace(r.FormValue("php_version"))
		if siteName == "" || phpVersion == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "site name and php version are required"})
			return
		}
		site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "managed site could not be found"})
			return
		}
		helperAction = "php.switch"
		payload = map[string]any{"config_path": site.NginxConfigPath, "version": phpVersion}
		auditAction = "php.switch"
		target = siteName
		label = "switch php version"
		auditMeta = map[string]any{"version": phpVersion, "config_path": site.NginxConfigPath}
		afterSuccess = func() error {
			return a.store.UpdateManagedSitePHPVersion(r.Context(), siteName, phpVersion)
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported php action"})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return
	}
	streamWriter := &flushWriter{writer: w, flusher: flusher}
	_, _ = io.WriteString(streamWriter, "$ "+label+"\n\n")
	if err := a.streamHelperAction(r.Context(), streamWriter, helperAction, payload); err != nil {
		failureMeta := map[string]any{"error": err.Error()}
		for key, value := range auditMeta {
			failureMeta[key] = value
		}
		a.recordAudit(r.Context(), auditAction, target, "failure", failureMeta)
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	if afterSuccess != nil {
		if err := afterSuccess(); err != nil {
			a.recordAudit(r.Context(), auditAction, target, "failure", map[string]any{"error": err.Error(), "stage": "post_update"})
			_, _ = io.WriteString(streamWriter, "\n\n[command completed, but local state update failed]\n")
			return
		}
	}
	a.recordAudit(r.Context(), auditAction, target, "success", auditMeta)
	_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
}

func (a *App) handleRedisStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	action := strings.TrimSpace(r.FormValue("redis_action"))
	status, _ := a.redis.Inspect()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return
	}
	streamWriter := &flushWriter{writer: w, flusher: flusher}

	switch action {
	case "install", "start", "stop", "restart":
		_, _ = io.WriteString(streamWriter, "$ redis "+action+"\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "redis."+action, map[string]any{}); err != nil {
			a.recordAudit(r.Context(), "redis."+action, status.ServiceName, "failure", map[string]any{"error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		a.recordAudit(r.Context(), "redis."+action, status.ServiceName, "success", nil)
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	case "save_config":
		username := strings.TrimSpace(r.FormValue("redis_username"))
		port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("redis_port")))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "redis port must be a valid number"})
			return
		}
		maxMemoryMB, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("redis_max_memory_mb")), 10, 64)
		if err != nil || maxMemoryMB < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "redis memory limit must be zero or a positive number in MB"})
			return
		}
		password := strings.TrimSpace(r.FormValue("redis_password"))
		generated := false
		if password == "" {
			secret, secretErr := randomPassword(24)
			if secretErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password generation failed"})
				return
			}
			password = secret
			generated = true
		}
		_, _ = io.WriteString(streamWriter, "$ redis configure\n\n")
		configSpec := system.RedisConfigSpec{Username: username, Password: password, Port: port, MaxMemoryBytes: maxMemoryMB * 1024 * 1024, EvictionPolicy: strings.TrimSpace(r.FormValue("redis_eviction_policy"))}
		if err := a.streamHelperAction(r.Context(), streamWriter, "redis.configure", configSpec); err != nil {
			a.recordAudit(r.Context(), "redis.configure", username, "failure", map[string]any{"port": port, "max_memory_mb": maxMemoryMB, "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		_, _ = io.WriteString(streamWriter, "\n\n$ redis restart\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "redis.restart", map[string]any{}); err != nil {
			a.recordAudit(r.Context(), "redis.restart", status.ServiceName, "failure", map[string]any{"after": "configure", "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[configuration saved, but restart failed]\n")
			return
		}
		if generated {
			_, _ = io.WriteString(streamWriter, "\nGenerated password: "+password+"\n")
		}
		a.recordAudit(r.Context(), "redis.configure", username, "success", map[string]any{"port": port, "max_memory_mb": maxMemoryMB, "eviction_policy": strings.TrimSpace(r.FormValue("redis_eviction_policy"))})
		a.recordAudit(r.Context(), "redis.restart", status.ServiceName, "success", map[string]any{"after": "configure"})
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	case "test_connection":
		username := strings.TrimSpace(r.FormValue("redis_username"))
		port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("redis_port")))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "redis port must be a valid number"})
			return
		}
		password := strings.TrimSpace(r.FormValue("redis_password"))
		_, _ = io.WriteString(streamWriter, "$ redis ping\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "redis.test_connection", system.RedisPingSpec{Username: username, Password: password, Port: port}); err != nil {
			a.recordAudit(r.Context(), "redis.test_connection", username, "failure", map[string]any{"port": port, "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		a.recordAudit(r.Context(), "redis.test_connection", username, "success", map[string]any{"port": port})
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported redis action"})
	}
}

func (a *App) handleDeploysStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	mode := strings.TrimSpace(r.FormValue("deploy_mode"))
	var (
		helperAction string
		payload any
		auditAction string
		target string
		label string
		auditMeta map[string]any
	)
	if mode == "rollback" {
		spec := system.RollbackSpec{
			TargetDirectory: strings.TrimSpace(r.FormValue("rollback_target_directory")),
			RunAsUser: strings.TrimSpace(r.FormValue("rollback_run_as_user")),
			ReleaseCommitSHA: strings.TrimSpace(r.FormValue("release_commit_sha")),
			PostDeployCommand: r.FormValue("rollback_post_deploy_command"),
		}
		helperAction = "deploy.rollback"
		payload = spec
		auditAction = "deploy.rollback"
		target = spec.TargetDirectory
		label = "rollback deploy"
		auditMeta = map[string]any{"run_as_user": spec.RunAsUser, "commit_sha": spec.ReleaseCommitSHA}
	} else {
		spec := system.DeploySpec{
			RepositoryURL: strings.TrimSpace(r.FormValue("repository_url")),
			Branch: strings.TrimSpace(r.FormValue("branch")),
			TargetDirectory: strings.TrimSpace(r.FormValue("target_directory")),
			RunAsUser: strings.TrimSpace(r.FormValue("run_as_user")),
			GitSiteName: strings.TrimSpace(r.FormValue("git_site_name")),
			PostDeployCommand: r.FormValue("post_deploy_command"),
		}
		helperAction = "deploy.run"
		payload = spec
		auditAction = "deploy.run"
		target = spec.TargetDirectory
		label = "run deploy"
		auditMeta = map[string]any{"repository_url": spec.RepositoryURL, "run_as_user": spec.RunAsUser}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return
	}
	streamWriter := &flushWriter{writer: w, flusher: flusher}
	_, _ = io.WriteString(streamWriter, "$ "+label+"\n\n")
	if err := a.streamHelperAction(r.Context(), streamWriter, helperAction, payload); err != nil {
		failureMeta := map[string]any{"error": err.Error()}
		for key, value := range auditMeta {
			failureMeta[key] = value
		}
		a.recordAudit(r.Context(), auditAction, target, "failure", failureMeta)
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	a.recordAudit(r.Context(), auditAction, target, "success", auditMeta)
	_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
}

func (a *App) handleProcessesStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	user := strings.TrimSpace(r.FormValue("run_as_user"))
	action := strings.TrimSpace(r.FormValue("action"))
	processName := strings.TrimSpace(r.FormValue("process_name"))
	logLines, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("log_lines")))
	if action == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "process action is required"})
		return
	}
	helpAction := "pm2." + action
	payload := map[string]any{"user": user, "process_name": processName, "lines": logLines}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return
	}
	streamWriter := &flushWriter{writer: w, flusher: flusher}
	_, _ = io.WriteString(streamWriter, "$ pm2 "+action+"\n\n")
	if err := a.streamHelperAction(r.Context(), streamWriter, helpAction, payload); err != nil {
		a.recordAudit(r.Context(), helpAction, processName, "failure", map[string]any{"run_as_user": user, "error": err.Error()})
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	a.recordAudit(r.Context(), helpAction, processName, "success", map[string]any{"run_as_user": user})
	_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
}

func streamResponseWriter(w http.ResponseWriter) (*flushWriter, bool) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return nil, false
	}
	return &flushWriter{writer: w, flusher: flusher}, true
}

func (a *App) handleSitesStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	streamWriter, ok := streamResponseWriter(w)
	if !ok {
		return
	}
	users := a.listLinuxUsers()
	action := strings.TrimSpace(r.FormValue("site_action"))
	if action == "" {
		action = "create"
	}
	sites := a.listManagedSites(r)
	switch action {
	case "create":
		spec := system.SiteSpec{
			Name:           strings.TrimSpace(r.FormValue("site_name")),
			OwnerLinuxUser: strings.TrimSpace(r.FormValue("owner_linux_user")),
			Domain:         strings.TrimSpace(r.FormValue("domain")),
			Mode:           strings.TrimSpace(r.FormValue("mode")),
			UpstreamURL:    strings.TrimSpace(r.FormValue("upstream_url")),
			PHPVersion:     strings.TrimSpace(r.FormValue("php_version")),
		}
		rootDirectory, err := buildManagedSiteRootDirectory(users, spec.OwnerLinuxUser, spec.Name)
		if err != nil {
			_, _ = io.WriteString(streamWriter, err.Error()+"\n")
			_, _ = io.WriteString(streamWriter, "\n[command failed]\n")
			return
		}
		spec.RootDirectory = rootDirectory
		switch spec.Mode {
		case "reverse_proxy":
			spec.PHPVersion = ""
		case "static":
			spec.UpstreamURL = ""
			spec.PHPVersion = ""
		case "php":
			spec.UpstreamURL = ""
		}
		_, _ = io.WriteString(streamWriter, "$ apply nginx site\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "nginx.apply_site", spec); err != nil {
			a.recordAudit(r.Context(), "nginx.apply_site", spec.Name, "failure", map[string]any{"domain": spec.Domain, "mode": spec.Mode, "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		configPath := filepath.Join(a.cfg.NginxAvailableDir, spec.Name+".conf")
		if a.store != nil {
			if err := a.store.CreateManagedSite(r.Context(), domain.ManagedSite{Name: spec.Name, OwnerLinuxUser: spec.OwnerLinuxUser, DomainName: spec.Domain, RootDirectory: spec.RootDirectory, Runtime: spec.Mode, UpstreamURL: spec.UpstreamURL, PHPVersion: spec.PHPVersion, NginxConfigPath: configPath}); err != nil {
				a.recordAudit(r.Context(), "nginx.apply_site", spec.Name, "failure", map[string]any{"domain": spec.Domain, "mode": spec.Mode, "config_path": configPath, "store_error": err.Error()})
				_, _ = io.WriteString(streamWriter, "\nPanel record save failed: "+err.Error()+"\n")
				_, _ = io.WriteString(streamWriter, "\n[command failed]\n")
				return
			}
		}
		a.recordAudit(r.Context(), "nginx.apply_site", spec.Name, "success", map[string]any{"domain": spec.Domain, "mode": spec.Mode, "config_path": configPath})
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	case "delete":
		if a.store == nil {
			_, _ = io.WriteString(streamWriter, "Managed site storage is not configured yet.\n\n[command failed]\n")
			return
		}
		if r.FormValue("confirm_delete") != "1" {
			_, _ = io.WriteString(streamWriter, "Site deletion was not confirmed.\n\n[command failed]\n")
			return
		}
		siteName := strings.TrimSpace(r.FormValue("delete_site_name"))
		site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
		if err != nil {
			a.recordAudit(r.Context(), "nginx.delete_site", siteName, "failure", map[string]any{"error": err.Error()})
			_, _ = io.WriteString(streamWriter, "Managed site could not be found by that name.\n\n[command failed]\n")
			return
		}
		_, _ = io.WriteString(streamWriter, "$ delete nginx site\n\n")
		payload := system.SiteRemoval{Name: site.Name, Domain: site.DomainName, RootDirectory: site.RootDirectory, ConfigPath: site.NginxConfigPath}
		if err := a.streamHelperAction(r.Context(), streamWriter, "nginx.delete_site", payload); err != nil {
			a.recordAudit(r.Context(), "nginx.delete_site", site.Name, "failure", map[string]any{"config_path": site.NginxConfigPath, "root_directory": site.RootDirectory, "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		if err := a.store.DeleteManagedSite(r.Context(), site.Name); err != nil {
			a.recordAudit(r.Context(), "nginx.delete_site", site.Name, "failure", map[string]any{"config_path": site.NginxConfigPath, "root_directory": site.RootDirectory, "error": err.Error(), "cleanup": "store"})
			_, _ = io.WriteString(streamWriter, "\nPanel record delete failed: "+err.Error()+"\n")
			_, _ = io.WriteString(streamWriter, "\n[command failed]\n")
			return
		}
		a.recordAudit(r.Context(), "nginx.delete_site", site.Name, "success", map[string]any{"config_path": site.NginxConfigPath, "root_directory": site.RootDirectory})
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	case "tls":
		request := system.TLSRequest{Domain: strings.TrimSpace(r.FormValue("tls_domain")), Email: strings.TrimSpace(r.FormValue("tls_email")), Redirect: r.FormValue("tls_redirect") == "1"}
		_, _ = io.WriteString(streamWriter, "$ request tls certificate\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "nginx.enable_tls", request); err != nil {
			a.recordAudit(r.Context(), "nginx.enable_tls", request.Domain, "failure", map[string]any{"email": request.Email, "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		a.recordAudit(r.Context(), "nginx.enable_tls", request.Domain, "success", map[string]any{"email": request.Email, "redirect": request.Redirect})
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	default:
		_, _ = io.WriteString(streamWriter, "Unsupported site action.\n\n[command failed]\n")
	}
	_ = sites
}

func (a *App) handleSettingsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	streamWriter, ok := streamResponseWriter(w)
	if !ok {
		return
	}
	action := strings.TrimSpace(r.FormValue("settings_action"))
	switch action {
	case "apply_panel_proxy":
		payload := system.PanelProxySpec{Domain: strings.TrimSpace(r.FormValue("panel_domain")), ListenAddr: strings.TrimSpace(r.FormValue("panel_listen_addr"))}
		if payload.Domain == "" {
			_, _ = io.WriteString(streamWriter, "Panel domain is required to apply the panel proxy.\n\n[command failed]\n")
			return
		}
		_, _ = io.WriteString(streamWriter, "$ apply panel proxy\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "panel.apply_proxy", payload); err != nil {
			a.recordAudit(r.Context(), "panel.proxy.apply", payload.Domain, "failure", map[string]any{"listen_addr": payload.ListenAddr, "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		a.recordAudit(r.Context(), "panel.proxy.apply", payload.Domain, "success", map[string]any{"listen_addr": payload.ListenAddr})
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	case "enable_panel_tls":
		payload := system.TLSRequest{Domain: strings.TrimSpace(r.FormValue("panel_domain")), Email: strings.TrimSpace(r.FormValue("panel_tls_email")), Redirect: r.FormValue("panel_tls_redirect") == "1"}
		if payload.Domain == "" || payload.Email == "" {
			_, _ = io.WriteString(streamWriter, "Panel domain and TLS email are required.\n\n[command failed]\n")
			return
		}
		_, _ = io.WriteString(streamWriter, "$ enable panel tls\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "nginx.enable_tls", payload); err != nil {
			a.recordAudit(r.Context(), "panel.tls.enable", payload.Domain, "failure", map[string]any{"email": payload.Email, "error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		a.recordAudit(r.Context(), "panel.tls.enable", payload.Domain, "success", map[string]any{"email": payload.Email})
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	case "restart_panel_service":
		serviceName := firstNonEmpty(strings.TrimSpace(r.FormValue("panel_service_name")), strings.TrimSpace(a.cfg.ServiceName), "server-side-control")
		_, _ = io.WriteString(streamWriter, "$ restart panel service\n\n")
		if err := a.streamHelperAction(r.Context(), streamWriter, "panel.restart_service", map[string]any{}); err != nil {
			a.recordAudit(r.Context(), "panel.service.restart", serviceName, "failure", map[string]any{"error": err.Error()})
			_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
			return
		}
		a.recordAudit(r.Context(), "panel.service.restart", serviceName, "success", nil)
		_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
	default:
		_, _ = io.WriteString(streamWriter, "Unsupported settings action.\n\n[command failed]\n")
	}
}

func (a *App) handleDatabaseDetailsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseMultipartForm(a.cfg.DatabaseRestoreMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	streamWriter, ok := streamResponseWriter(w)
	if !ok {
		return
	}
	action := strings.TrimSpace(r.FormValue("database_details_action"))
	if action != "restore" {
		_, _ = io.WriteString(streamWriter, "Unsupported database action.\n\n[command failed]\n")
		return
	}
	databaseName := strings.TrimSpace(r.FormValue("database_name"))
	if databaseName == "" {
		_, _ = io.WriteString(streamWriter, "Database name is required.\n\n[command failed]\n")
		return
	}
	tempPath, _, err := writeDatabaseRestoreTempFile(r, a.cfg.DatabaseRestoreMaxBytes)
	if err != nil {
		_, _ = io.WriteString(streamWriter, err.Error()+"\n\n[command failed]\n")
		return
	}
	defer os.Remove(tempPath)
	_, _ = io.WriteString(streamWriter, "$ restore database\n\n")
	if err := a.streamHelperAction(r.Context(), streamWriter, "mysql.restore_database", map[string]any{"database_name": databaseName, "file_path": tempPath}); err != nil {
		a.recordAudit(r.Context(), "database.restore", databaseName, "failure", map[string]any{"error": err.Error()})
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	a.recordAudit(r.Context(), "database.restore", databaseName, "success", nil)
	_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
}

func (a *App) handleSiteActionStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	siteName := strings.TrimSpace(r.FormValue("site_name"))
	if siteName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "site name is required"})
		return
	}
	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "managed site could not be found"})
		return
	}
	action := strings.TrimSpace(r.FormValue("details_action"))
	var (
		helperAction string
		payload      any
		auditAction  string
		label        string
		auditMeta    map[string]any
		previousCommit string
		appendRepoState bool
	)
	targetDirectory := site.RootDirectory
	targetUser := site.OwnerLinuxUser
	targetLabel := site.Name
	if subdomainID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64); err == nil && subdomainID > 0 {
		if subdomains, listErr := a.store.ListSiteSubdomains(r.Context(), site.ID); listErr == nil {
			if subdomain, ok := findSiteSubdomain(subdomains, subdomainID); ok {
				targetDirectory = subdomain.RootDirectory
				targetLabel = subdomain.FullDomain
			}
		}
	}
	switch action {
	case "sync_repository":
		repositoryURL := strings.TrimSpace(r.FormValue("repository_url"))
		if repositoryURL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "repository url is required"})
			return
		}
		branch := strings.TrimSpace(r.FormValue("branch"))
		if branch == "" {
			branch = "main"
		}
		postDeployCommand := r.FormValue("post_deploy_command")
		helperAction = "deploy.run"
		payload = system.DeploySpec{
			RepositoryURL:     repositoryURL,
			Branch:            branch,
			TargetDirectory:   site.RootDirectory,
			RunAsUser:         site.OwnerLinuxUser,
			GitSiteName:       site.Name,
			PostDeployCommand: postDeployCommand,
		}
		auditAction = "deploy.site_sync"
		label = "git sync"
		auditMeta = map[string]any{"repository_url": repositoryURL, "branch": branch, "run_as_user": site.OwnerLinuxUser, "target_directory": site.RootDirectory}
		appendRepoState = true
		if status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser}); inspectErr == nil {
			previousCommit = strings.TrimSpace(status.CurrentCommit)
		}
	case "sync_subdomain_repository":
		subdomainID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64)
		if err != nil || subdomainID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subdomain id is required"})
			return
		}
		subdomains, listErr := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if listErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load subdomains"})
			return
		}
		subdomain, ok := findSiteSubdomain(subdomains, subdomainID)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subdomain could not be found"})
			return
		}
		if strings.TrimSpace(subdomain.RepositoryURL) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subdomain repository url is required"})
			return
		}
		targetDirectory = subdomain.RootDirectory
		targetLabel = subdomain.FullDomain
		helperAction = "deploy.run"
		payload = system.DeploySpec{
			RepositoryURL:     subdomain.RepositoryURL,
			Branch:            firstNonEmpty(subdomain.BranchName, "main"),
			TargetDirectory:   subdomain.RootDirectory,
			RunAsUser:         targetUser,
			GitSiteName:       subdomain.FullDomain,
			PostDeployCommand: subdomain.PostDeployCommand,
		}
		auditAction = "deploy.subdomain_sync"
		label = "git sync " + subdomain.FullDomain
		auditMeta = map[string]any{"repository_url": subdomain.RepositoryURL, "branch": firstNonEmpty(subdomain.BranchName, "main"), "run_as_user": targetUser, "target_directory": subdomain.RootDirectory, "subdomain_id": subdomain.ID}
		appendRepoState = true
		if status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: subdomain.RootDirectory, RunAsUser: targetUser}); inspectErr == nil {
			previousCommit = strings.TrimSpace(status.CurrentCommit)
		}
	case "run_subdomain_git_command":
		subdomainID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64)
		if err != nil || subdomainID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subdomain id is required"})
			return
		}
		command := strings.TrimSpace(r.FormValue("git_custom_command"))
		if command == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "custom git command is required"})
			return
		}
		if err := system.ValidateGitCommand(command); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "custom git command must be a single safe git command"})
			return
		}
		subdomains, listErr := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if listErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load subdomains"})
			return
		}
		subdomain, ok := findSiteSubdomain(subdomains, subdomainID)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subdomain could not be found"})
			return
		}
		targetDirectory = subdomain.RootDirectory
		targetLabel = subdomain.FullDomain
		helperAction = "deploy.run_custom_git_command"
		payload = system.GitCommandSpec{User: targetUser, WorkingDirectory: subdomain.RootDirectory, Command: command}
		auditAction = "deploy.subdomain_custom_git_command"
		label = command + " · " + subdomain.FullDomain
		auditMeta = map[string]any{"run_as_user": targetUser, "target_directory": subdomain.RootDirectory, "command": command, "subdomain_id": subdomain.ID}
		appendRepoState = true
		if status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: subdomain.RootDirectory, RunAsUser: targetUser}); inspectErr == nil {
			previousCommit = strings.TrimSpace(status.CurrentCommit)
		}
	case "generate_subdomain_deploy_key":
		subdomainID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64)
		if err != nil || subdomainID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subdomain id is required"})
			return
		}
		subdomains, listErr := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if listErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load subdomains"})
			return
		}
		subdomain, ok := findSiteSubdomain(subdomains, subdomainID)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subdomain could not be found"})
			return
		}
		targetLabel = subdomain.FullDomain
		helperAction = "git_auth.ensure_deploy_key"
		payload = system.GitDeployKeySpec{User: site.OwnerLinuxUser, SiteName: subdomain.FullDomain, RepositoryURL: firstNonEmpty(strings.TrimSpace(r.FormValue("repository_url")), subdomain.RepositoryURL)}
		auditAction = "git_auth.subdomain.ensure_deploy_key"
		label = "generate deploy key " + subdomain.FullDomain
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser, "subdomain_id": subdomain.ID}
	case "trust_subdomain_git_host":
		subdomainID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64)
		if err != nil || subdomainID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subdomain id is required"})
			return
		}
		host := strings.TrimSpace(r.FormValue("credential_host"))
		if host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "git host is required"})
			return
		}
		subdomains, listErr := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if listErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load subdomains"})
			return
		}
		subdomain, ok := findSiteSubdomain(subdomains, subdomainID)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subdomain could not be found"})
			return
		}
		targetLabel = subdomain.FullDomain
		helperAction = "git_auth.trust_host"
		payload = system.GitHostTrustSpec{User: site.OwnerLinuxUser, Host: host}
		auditAction = "git_auth.subdomain.trust_host"
		label = "trust host " + host + " · " + subdomain.FullDomain
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser, "host": host, "subdomain_id": subdomain.ID}
	case "run_custom_git_command":
		command := strings.TrimSpace(r.FormValue("git_custom_command"))
		if command == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "custom git command is required"})
			return
		}
		if err := system.ValidateGitCommand(command); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "custom git command must be a single safe git command"})
			return
		}
		helperAction = "deploy.run_custom_git_command"
		payload = system.GitCommandSpec{User: site.OwnerLinuxUser, WorkingDirectory: site.RootDirectory, Command: command}
		auditAction = "deploy.custom_git_command"
		label = command
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser, "target_directory": site.RootDirectory, "command": command}
		appendRepoState = true
		if status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser}); inspectErr == nil {
			previousCommit = strings.TrimSpace(status.CurrentCommit)
		}
	case "generate_deploy_key":
		helperAction = "git_auth.ensure_deploy_key"
		payload = system.GitDeployKeySpec{User: site.OwnerLinuxUser, SiteName: site.Name, RepositoryURL: strings.TrimSpace(r.FormValue("repository_url"))}
		auditAction = "git_auth.ensure_deploy_key"
		label = "generate deploy key"
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser}
	case "trust_git_host":
		host := strings.TrimSpace(r.FormValue("credential_host"))
		if host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "git host is required"})
			return
		}
		helperAction = "git_auth.trust_host"
		payload = system.GitHostTrustSpec{User: site.OwnerLinuxUser, Host: host}
		auditAction = "git_auth.trust_host"
		label = "trust host " + host
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser, "host": host}
	case "run_ssh_command":
		workingDirectory := strings.TrimSpace(r.FormValue("ssh_working_directory"))
		commandBody := r.FormValue("ssh_command_body")
		if workingDirectory == "" {
			workingDirectory = site.RootDirectory
		}
		if strings.TrimSpace(commandBody) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "shell command is required"})
			return
		}
		helperAction = "runtime.run_shell_command"
		payload = system.ShellCommandSpec{User: site.OwnerLinuxUser, WorkingDirectory: workingDirectory, CommandBody: commandBody}
		auditAction = "site.ssh_console"
		label = "shell as " + site.OwnerLinuxUser
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser, "working_directory": workingDirectory}
	case "fix_laravel_permissions":
		if _, hasArtisan := a.detectProjectMarkers(r.Context(), targetDirectory); !hasArtisan {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "laravel project was not detected in this site root"})
			return
		}
		helperAction = "site.fix_laravel_permissions"
		payload = map[string]any{"root_dir": targetDirectory, "owner_user": site.OwnerLinuxUser}
		auditAction = "site.fix_laravel_permissions"
		label = "fix laravel permissions"
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser, "target_directory": targetDirectory}
	case "clear_root_contents":
		helperAction = "files.clear_directory"
		payload = map[string]any{"path": targetDirectory}
		auditAction = "site.clear_root_contents"
		label = "clear root contents"
		auditMeta = map[string]any{"target_directory": targetDirectory, "run_as_user": site.OwnerLinuxUser}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported site action"})
		return
	}

	requestPayload, err := json.Marshal(system.HelperRequest{Action: helperAction, Input: mustMarshal(payload)})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encode helper request"})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = io.WriteString(w, "streaming is not supported by this server\n")
		return
	}
	streamWriter := &flushWriter{writer: w, flusher: flusher}
	_, _ = io.WriteString(streamWriter, "$ "+label+"\n\n")

	cmd := exec.CommandContext(r.Context(), "sudo", "-n", a.cfg.HelperBinary, "stream-action")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stdin: %v\n", err))
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stdout: %v\n", err))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not open helper stderr: %v\n", err))
		return
	}
	if err := cmd.Start(); err != nil {
		_, _ = io.WriteString(streamWriter, fmt.Sprintf("could not start helper: %v\n", err))
		return
	}
	go func() {
		_, _ = stdin.Write(requestPayload)
		_ = stdin.Close()
	}()

	var output bytes.Buffer
	multiOut := io.MultiWriter(streamWriter, &output)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(multiOut, stdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(multiOut, stderr)
	}()
	err = cmd.Wait()
	wg.Wait()
	if err != nil {
		failureMeta := map[string]any{"label": label, "error": err.Error()}
		for key, value := range auditMeta {
			failureMeta[key] = value
		}
		a.recordAudit(r.Context(), auditAction, targetLabel, "failure", failureMeta)
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	successMeta := map[string]any{"label": label}
	for key, value := range auditMeta {
		successMeta[key] = value
	}
	a.recordAudit(r.Context(), auditAction, targetLabel, "success", successMeta)
	if appendRepoState {
		if status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: targetDirectory, RunAsUser: targetUser}); inspectErr == nil && status.IsGitRepo {
			_, _ = io.WriteString(streamWriter, "\n")
			if strings.TrimSpace(status.Branch) != "" {
				_, _ = io.WriteString(streamWriter, "Branch: "+strings.TrimSpace(status.Branch)+"\n")
			}
			if previousCommit != "" && previousCommit != strings.TrimSpace(status.CurrentCommit) {
				_, _ = io.WriteString(streamWriter, "Previous commit: "+previousCommit+"\n")
			}
			if strings.TrimSpace(status.CurrentCommit) != "" {
				_, _ = io.WriteString(streamWriter, "Current commit: "+strings.TrimSpace(status.CurrentCommit)+"\n")
			}
		}
	}
	_, _ = io.WriteString(streamWriter, "\n\n[command completed]\n")
}

func mustMarshal(value any) json.RawMessage {
	payload, _ := json.Marshal(value)
	return payload
}