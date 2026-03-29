package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"

	"github.com/kaganyegin/server-side-control/internal/system"
)

type flushWriter struct {
	mu      sync.Mutex
	writer  http.ResponseWriter
	flusher http.Flusher
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
	var (
		helperAction string
		payload      any
		auditAction  string
		label        string
	)
	switch action {
	case "npm_install":
		nodeVersion := strings.TrimSpace(r.FormValue("npm_script_node_version"))
		ci := r.FormValue("npm_ci") == "1"
		helperAction = "runtime.run_npm_install"
		payload = system.NPMInstallSpec{
			User:             site.OwnerLinuxUser,
			WorkingDirectory: site.RootDirectory,
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
			WorkingDirectory: site.RootDirectory,
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
			WorkingDirectory: site.RootDirectory,
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
		a.recordAudit(r.Context(), auditAction, site.Name, "failure", map[string]any{"label": label, "error": err.Error()})
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	a.recordAudit(r.Context(), auditAction, site.Name, "success", map[string]any{"label": label})
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
			PostDeployCommand: postDeployCommand,
		}
		auditAction = "deploy.site_sync"
		label = "git sync"
		auditMeta = map[string]any{"repository_url": repositoryURL, "branch": branch, "run_as_user": site.OwnerLinuxUser, "target_directory": site.RootDirectory}
		appendRepoState = true
		if status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser}); inspectErr == nil {
			previousCommit = strings.TrimSpace(status.CurrentCommit)
		}
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
	case "store_git_credential":
		protocol := strings.TrimSpace(r.FormValue("credential_protocol"))
		host := strings.TrimSpace(r.FormValue("credential_host"))
		username := strings.TrimSpace(r.FormValue("credential_username"))
		password := r.FormValue("credential_password")
		if host == "" || username == "" || strings.TrimSpace(password) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential host, username, and password are required"})
			return
		}
		helperAction = "git_auth.store_credential"
		payload = system.GitCredentialSpec{User: site.OwnerLinuxUser, Protocol: protocol, Host: host, Username: username, Password: password}
		auditAction = "git_auth.store_credential"
		label = "store git credentials"
		auditMeta = map[string]any{"run_as_user": site.OwnerLinuxUser, "protocol": protocol, "host": host, "username": username}
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
		a.recordAudit(r.Context(), auditAction, site.Name, "failure", failureMeta)
		_, _ = io.WriteString(streamWriter, "\n\n[command failed]\n")
		return
	}
	successMeta := map[string]any{"label": label}
	for key, value := range auditMeta {
		successMeta[key] = value
	}
	a.recordAudit(r.Context(), auditAction, site.Name, "success", successMeta)
	if appendRepoState {
		if status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser}); inspectErr == nil && status.IsGitRepo {
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