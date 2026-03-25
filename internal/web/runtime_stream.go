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
	nodeVersion := strings.TrimSpace(r.FormValue("npm_script_node_version"))
	var (
		helperAction string
		payload      any
		auditAction  string
		label        string
	)
	switch action {
	case "npm_install":
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

func mustMarshal(value any) json.RawMessage {
	payload, _ := json.Marshal(value)
	return payload
}