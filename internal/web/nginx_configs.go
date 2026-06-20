package web

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kaganyegin/server-side-control/internal/system"
)

// NginxConfigFile is one file in the nginx sites-available directory as shown on
// the Nginx configs page.
type NginxConfigFile struct {
	Name    string   // file base name, e.g. "default"
	Path    string   // absolute sites-available path
	Enabled bool     // true when symlinked into sites-enabled
	Domains []string // server_name values found inside (for recognition)
	Managed string   // panel site name that owns this config, if any
}

func (a *App) handleNginxConfigs(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{
		Title:          "Nginx",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
	}

	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			data.RequestError = "The submitted form could not be parsed."
		} else {
			a.handleNginxConfigAction(r, &data)
		}
	case http.MethodGet:
		if editName := strings.TrimSpace(r.URL.Query().Get("edit")); editName != "" {
			a.loadNginxConfigEditor(r.Context(), editName, &data)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	files, notices := a.listNginxConfigFiles(r.Context())
	data.NginxConfigFiles = files
	data.NginxConfigNotices = append(data.NginxConfigNotices, notices...)
	a.render(r.Context(), w, "/nginx", "nginx_configs.html", data)
}

func (a *App) handleNginxConfigAction(r *http.Request, data *TemplateData) {
	action := strings.TrimSpace(r.FormValue("nginx_action"))
	name := strings.TrimSpace(r.FormValue("nginx_config_name"))
	if !system.IsSafeNginxConfigName(name) {
		data.RequestError = "Invalid Nginx config name."
		return
	}
	availablePath := filepath.Join(a.cfg.NginxAvailableDir, name)
	if !isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, availablePath) {
		data.RequestError = "Config path is outside the managed Nginx directory."
		return
	}

	switch action {
	case "set_enabled":
		enabled := r.FormValue("nginx_config_enabled") == "1"
		if _, err := a.helper.Call(r.Context(), "nginx.set_config_enabled", map[string]any{"name": name, "enabled": enabled}, nil); err != nil {
			data.RequestError = "Could not change config state: " + err.Error()
			a.recordAudit(r.Context(), "nginx.set_config_enabled", name, "failure", map[string]any{"enabled": enabled, "error": err.Error()})
			return
		}
		a.recordAudit(r.Context(), "nginx.set_config_enabled", name, "success", map[string]any{"enabled": enabled})
		if enabled {
			data.SuccessMessage = name + " enabled and Nginx reloaded."
		} else {
			data.SuccessMessage = name + " disabled and Nginx reloaded."
		}
	case "validate_config":
		content := r.FormValue("nginx_config_content")
		data.NginxEditName = name
		data.NginxEditContent = content
		out, err := a.helper.Call(r.Context(), "nginx.validate_config", map[string]string{"path": availablePath, "content": content}, nil)
		if err != nil {
			data.RequestError = "Validation failed: " + err.Error()
			return
		}
		data.CommandOutput = out
		data.SuccessMessage = "Nginx config is valid (not saved)."
	case "save_config":
		content := r.FormValue("nginx_config_content")
		if err := a.saveNginxFile(r.Context(), availablePath, content); err != nil {
			data.NginxEditName = name
			data.NginxEditContent = content
			data.RequestError = err.Error()
			a.recordAudit(r.Context(), "nginx.write_config", name, "failure", map[string]any{"error": err.Error()})
			return
		}
		a.recordAudit(r.Context(), "nginx.write_config", name, "success", nil)
		data.SuccessMessage = name + " saved and Nginx reloaded."
	default:
		data.RequestError = "Unknown Nginx config action."
	}
}

// saveNginxFile writes content to an nginx config file via the privileged
// helper, validates with nginx -t, reloads, and restores the previous content
// on any failure. Unlike saveNginxConfigContent it is not tied to a panel site.
func (a *App) saveNginxFile(ctx context.Context, configPath string, content string) error {
	var previous string
	_, _ = a.helper.Call(ctx, "files.read_text", map[string]any{"path": configPath, "max_bytes": 1048576}, &previous)
	if _, err := a.helper.Call(ctx, "nginx.write_config", map[string]string{"path": configPath, "content": content}, nil); err != nil {
		return fmt.Errorf("could not write Nginx config: %w", err)
	}
	if err := a.nginx.ValidateConfig(configPath); err != nil {
		_, _ = a.helper.Call(ctx, "nginx.write_config", map[string]string{"path": configPath, "content": previous}, nil)
		return fmt.Errorf("Nginx config validation failed, previous config restored: %w", err)
	}
	if err := a.nginx.Reload(); err != nil {
		_, _ = a.helper.Call(ctx, "nginx.write_config", map[string]string{"path": configPath, "content": previous}, nil)
		_ = a.nginx.Reload()
		return fmt.Errorf("Nginx reload failed, previous config restored: %w", err)
	}
	return nil
}

func (a *App) loadNginxConfigEditor(ctx context.Context, name string, data *TemplateData) {
	if !system.IsSafeNginxConfigName(name) {
		data.RequestError = "Invalid Nginx config name."
		return
	}
	full := filepath.Join(a.cfg.NginxAvailableDir, name)
	if !isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, full) {
		data.RequestError = "Config path is outside the managed Nginx directory."
		return
	}
	var content string
	if _, err := a.helper.Call(ctx, "files.read_text", map[string]any{"path": full, "max_bytes": 1048576}, &content); err != nil {
		data.RequestError = "Could not read config: " + err.Error()
		return
	}
	data.NginxEditName = name
	data.NginxEditContent = content
}

// listNginxConfigFiles lists every file in the nginx sites-available directory,
// marks which are enabled (symlinked into sites-enabled) and which belong to a
// panel-managed site, and extracts each file's server_name values.
func (a *App) listNginxConfigFiles(ctx context.Context) ([]NginxConfigFile, []string) {
	var notices []string
	if a.helper == nil {
		return nil, []string{"The privileged helper is not configured, so Nginx configs cannot be read."}
	}
	availableDir := strings.TrimSpace(a.cfg.NginxAvailableDir)
	if availableDir == "" {
		availableDir = "/etc/nginx/sites-available"
	}
	enabledDir := strings.TrimSpace(a.cfg.NginxEnabledDir)
	if enabledDir == "" {
		enabledDir = "/etc/nginx/sites-enabled"
	}

	enabledSet := make(map[string]struct{})
	var enabledEntries []helperSiteFileEntry
	if _, err := a.helper.Call(ctx, "files.list_dir", map[string]string{"path": enabledDir}, &enabledEntries); err == nil {
		for _, e := range enabledEntries {
			enabledSet[strings.TrimSpace(e.Name)] = struct{}{}
		}
	}

	managed := make(map[string]string)
	if a.store != nil {
		if sites, err := a.store.ListManagedSites(ctx); err == nil {
			for _, s := range sites {
				if p := strings.TrimSpace(s.NginxConfigPath); p != "" {
					managed[filepath.Base(p)] = s.Name
				}
			}
		}
	}

	var available []helperSiteFileEntry
	if _, err := a.helper.Call(ctx, "files.list_dir", map[string]string{"path": availableDir}, &available); err != nil {
		notices = append(notices, fmt.Sprintf("Could not list %s: %v", availableDir, err))
		return nil, notices
	}

	files := make([]NginxConfigFile, 0, len(available))
	for _, e := range available {
		if e.IsDir {
			continue
		}
		name := strings.TrimSpace(e.Name)
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		full := filepath.Join(availableDir, name)
		file := NginxConfigFile{Name: name, Path: full, Managed: managed[name]}
		if _, ok := enabledSet[name]; ok {
			file.Enabled = true
		}
		var content string
		if _, err := a.helper.Call(ctx, "files.read_text", map[string]any{"path": full, "max_bytes": 1048576}, &content); err == nil {
			file.Domains = nginxServerNamesIn(content)
		}
		files = append(files, file)
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, notices
}

// nginxServerNamesIn returns the distinct server_name values declared anywhere
// in an nginx config, excluding the catch-all "_".
func nginxServerNamesIn(content string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, block := range system.ParseNginxServerBlocks(content) {
		for _, d := range block.ServerNames {
			d = strings.TrimSpace(d)
			if d == "" || d == "_" {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}
