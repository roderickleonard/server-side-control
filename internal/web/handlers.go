package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kaganyegin/server-side-control/internal/auth"
	"github.com/kaganyegin/server-side-control/internal/domain"
	"github.com/kaganyegin/server-side-control/internal/system"
)

func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if _, err := a.currentSession(r); err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title: "Login",
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title:        "Login",
			RequestError: "The submitted form could not be parsed.",
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	identity, err := a.auth.Authenticate(r.Context(), username, password)
	if err != nil {
		a.recordAudit(r.Context(), "auth.login", username, "failure", map[string]any{"provider": "login-form"})
		message := "Invalid username or password."
		if errors.Is(err, auth.ErrUnsupported) {
			message = "PAM authentication is not available on this host. Use the bootstrap account until the Ubuntu target environment is ready."
		}
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title:        "Login",
			RequestError: message,
		})
		return
	}

	session, err := a.sessions.Create(r.Context(), *identity, a.clientAddress(r))
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	ctx := auth.ContextWithIdentity(r.Context(), *identity)
	a.recordAudit(ctx, "auth.login", identity.Username, "success", map[string]any{"provider": identity.AuthProvider})
	a.setSessionCookie(w, session)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.recordAudit(r.Context(), "auth.logout", "session", "success", nil)
	if cookie, err := r.Cookie(a.cfg.SessionCookieName); err == nil {
		a.sessions.Delete(r.Context(), cookie.Value)
	}
	a.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	snapshot := a.metrics.Snapshot()
	alerts := append([]string{}, snapshot.Alerts...)
	if a.store == nil {
		alerts = append(alerts, "MySQL connection is not configured yet.")
	}

	a.render(r.Context(), w, r.URL.Path, "dashboard.html", TemplateData{
		Title:          "Dashboard",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        snapshot,
		Alerts:         alerts,
	})
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{
		Title:           "Settings",
		DatabaseStatus:  a.databaseStatus(r.Context()),
		Metrics:         a.metrics.Snapshot(),
		PanelListenAddr: a.cfg.ListenAddr,
		PanelBaseURL:    a.cfg.BaseURL,
		PanelServiceName: firstNonEmpty(a.cfg.ServiceName, "server-side-control"),
		SMTPHost:        a.cfg.SMTPHost,
		SMTPPort:        firstNonEmpty(a.cfg.SMTPPort, "587"),
		SMTPUsername:    a.cfg.SMTPUsername,
		SMTPPassword:    a.cfg.SMTPPassword,
		SMTPFrom:        a.cfg.SMTPFrom,
		SMTPTo:          a.cfg.SMTPTo,
		PanelEnvPath:    a.cfg.EnvPath,
	}
	data.PanelDomain = panelDomainFromBaseURL(a.cfg.BaseURL)
	data.PanelProxyConfigPath = filepath.Join(a.cfg.NginxAvailableDir, "server-side-control-panel.conf")
	if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]string{"path": data.PanelProxyConfigPath}, &data.PanelProxyConfig); err != nil {
		data.PanelProxyConfig = ""
	}
	if data.PanelDomain != "" {
		_, _ = a.helper.Call(r.Context(), "panel.inspect_tls", map[string]string{"domain": data.PanelDomain}, &data.PanelTLSStatus)
	}

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "settings.html", data)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		data.RequestError = "The submitted settings form could not be parsed."
		a.render(r.Context(), w, r.URL.Path, "settings.html", data)
		return
	}

	data.PanelListenAddr = strings.TrimSpace(r.FormValue("panel_listen_addr"))
	data.PanelBaseURL = strings.TrimSpace(r.FormValue("panel_base_url"))
	data.PanelDomain = strings.TrimSpace(r.FormValue("panel_domain"))
	data.PanelTLSEmail = strings.TrimSpace(r.FormValue("panel_tls_email"))
	data.PanelServiceName = firstNonEmpty(strings.TrimSpace(r.FormValue("panel_service_name")), data.PanelServiceName)
	data.SMTPHost = strings.TrimSpace(r.FormValue("smtp_host"))
	data.SMTPPort = firstNonEmpty(strings.TrimSpace(r.FormValue("smtp_port")), "587")
	data.SMTPUsername = strings.TrimSpace(r.FormValue("smtp_username"))
	data.SMTPPassword = r.FormValue("smtp_password")
	data.SMTPFrom = strings.TrimSpace(r.FormValue("smtp_from"))
	data.SMTPTo = strings.TrimSpace(r.FormValue("smtp_to"))
	if data.PanelDomain == "" {
		data.PanelDomain = panelDomainFromBaseURL(data.PanelBaseURL)
	}

	switch r.FormValue("settings_action") {
	case "save_panel_settings":
		if data.PanelListenAddr == "" {
			data.RequestError = "Panel listen address is required."
			break
		}
		if _, err := url.ParseRequestURI(data.PanelBaseURL); err != nil {
			data.RequestError = "Panel base URL is invalid."
			break
		}
		updatedCfg := a.cfg
		updatedCfg.ListenAddr = data.PanelListenAddr
		updatedCfg.BaseURL = data.PanelBaseURL
		updatedCfg.ServiceName = data.PanelServiceName
		updatedCfg.SMTPHost = data.SMTPHost
		updatedCfg.SMTPPort = data.SMTPPort
		updatedCfg.SMTPUsername = data.SMTPUsername
		updatedCfg.SMTPPassword = data.SMTPPassword
		updatedCfg.SMTPFrom = data.SMTPFrom
		updatedCfg.SMTPTo = data.SMTPTo
		resultPath, err := a.helper.Call(r.Context(), "panel.write_env", map[string]string{"content": updatedCfg.ToEnv()}, nil)
		if err != nil {
			data.RequestError = "Panel config could not be saved: " + err.Error()
			break
		}
		a.cfg = updatedCfg
		data.ResultPath = resultPath
		data.SuccessMessage = "Panel settings saved. Restart the service if listen address changed."
		a.recordAudit(r.Context(), "panel.settings.save", "panel", "success", map[string]any{"base_url": updatedCfg.BaseURL, "listen_addr": updatedCfg.ListenAddr})
	case "test_smtp_settings":
		testCfg := a.cfg
		testCfg.SMTPHost = data.SMTPHost
		testCfg.SMTPPort = data.SMTPPort
		testCfg.SMTPUsername = data.SMTPUsername
		testCfg.SMTPPassword = data.SMTPPassword
		testCfg.SMTPFrom = data.SMTPFrom
		testCfg.SMTPTo = data.SMTPTo
		if err := sendSMTPTestEmail(testCfg); err != nil {
			data.RequestError = "SMTP test mail could not be sent: " + err.Error()
			break
		}
		data.SuccessMessage = "SMTP test mail sent successfully."
		a.recordAudit(r.Context(), "panel.smtp.test", data.SMTPTo, "success", nil)
	case "apply_panel_proxy":
		if data.PanelDomain == "" {
			data.RequestError = "Panel domain is required to apply the panel proxy."
			break
		}
		resultPath, err := a.helper.Call(r.Context(), "panel.apply_proxy", system.PanelProxySpec{Domain: data.PanelDomain, ListenAddr: data.PanelListenAddr}, nil)
		if err != nil {
			data.RequestError = "Panel proxy config could not be applied: " + err.Error()
			break
		}
		data.ResultPath = resultPath
		data.SuccessMessage = "Panel domain proxy applied to Nginx successfully."
		a.recordAudit(r.Context(), "panel.proxy.apply", data.PanelDomain, "success", map[string]any{"listen_addr": data.PanelListenAddr})
	case "enable_panel_tls":
		if data.PanelDomain == "" {
			data.RequestError = "Panel domain is required for TLS."
			break
		}
		if data.PanelTLSEmail == "" {
			data.RequestError = "TLS email is required."
			break
		}
		output, err := a.nginx.EnableTLS(system.TLSRequest{Domain: data.PanelDomain, Email: data.PanelTLSEmail, Redirect: r.FormValue("panel_tls_redirect") == "1"})
		if err != nil {
			data.RequestError = "Panel TLS could not be enabled: " + err.Error()
			break
		}
		data.CommandOutput = output
		data.SuccessMessage = "Panel TLS enabled successfully."
		a.recordAudit(r.Context(), "panel.tls.enable", data.PanelDomain, "success", map[string]any{"email": data.PanelTLSEmail})
	case "restart_panel_service":
		output, err := a.helper.Call(r.Context(), "panel.restart_service", nil, nil)
		if err != nil {
			data.RequestError = "Panel service could not be restarted: " + err.Error()
			break
		}
		data.CommandOutput = output
		data.SuccessMessage = "Panel service restart scheduled successfully."
		a.recordAudit(r.Context(), "panel.service.restart", data.PanelServiceName, "success", nil)
	default:
		data.RequestError = "Invalid settings action."
	}

	if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]string{"path": data.PanelProxyConfigPath}, &data.PanelProxyConfig); err != nil {
		data.PanelProxyConfig = ""
	}
	if data.PanelDomain != "" {
		_, _ = a.helper.Call(r.Context(), "panel.inspect_tls", map[string]string{"domain": data.PanelDomain}, &data.PanelTLSStatus)
	}
	a.render(r.Context(), w, r.URL.Path, "settings.html", data)
}

func panelDomainFromBaseURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	return host
}

func siteDetailTabForAction(action string) string {
	switch action {
	case "sync_repository", "generate_deploy_key", "trust_git_host", "store_git_credential", "save_auto_deploy", "rotate_auto_deploy_secret":
		return "deploy"
	case "install_nvm", "install_node", "install_pm2", "start_pm2", "restart_pm2", "reload_pm2", "stop_pm2", "run_npm_script", "npm_install", "save_runtime_command", "delete_runtime_command":
		return "runtime"
	case "enable_tls", "add_subdomain", "delete_subdomain", "enable_subdomain_tls":
		return "domains"
	case "assign_database", "assign_linux_user", "edit_env":
		return "settings"
	default:
		return "overview"
	}
}

func buildAutoDeployWebhookURL(baseURL string, siteName string, secret string) string {
	baseURL = strings.TrimSpace(baseURL)
	siteName = strings.TrimSpace(siteName)
	secret = strings.TrimSpace(secret)
	if baseURL == "" || siteName == "" || secret == "" {
		return ""
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	parsed.Path = "/webhooks/site-deploy"
	query := parsed.Query()
	query.Set("site", siteName)
	query.Set("secret", secret)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func buildWebhookBranch(payload []byte) string {
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		return ""
	}
	ref, _ := body["ref"].(string)
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "refs/heads/")
	return ref
}

func verifyWebhookSecret(r *http.Request, payload []byte, secret string) (string, bool) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "none", false
	}
	if signature := strings.TrimSpace(r.Header.Get("X-Hub-Signature-256")); signature != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(payload)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		return "github-sha256", subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) == 1
	}
	if signature := strings.TrimSpace(r.Header.Get("X-Hub-Signature")); signature != "" {
		mac := hmac.New(sha1.New, []byte(secret))
		_, _ = mac.Write(payload)
		expected := "sha1=" + hex.EncodeToString(mac.Sum(nil))
		return "github-sha1", subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) == 1
	}
	if token := strings.TrimSpace(r.Header.Get("X-Gitlab-Token")); token != "" {
		return "gitlab-token", subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1
	}
	if signature := strings.TrimSpace(r.Header.Get("X-Gitea-Signature")); signature != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(payload)
		expected := hex.EncodeToString(mac.Sum(nil))
		return "gitea-sha256", subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) == 1
	}
	if token := strings.TrimSpace(r.Header.Get("X-Webhook-Token")); token != "" {
		return "generic-header", subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1
	}
	if token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); token != "" && token != r.Header.Get("Authorization") {
		return "bearer", subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1
	}
	querySecret := strings.TrimSpace(r.URL.Query().Get("secret"))
	if querySecret != "" {
		return "query-secret", subtle.ConstantTimeCompare([]byte(querySecret), []byte(secret)) == 1
	}
	return "missing", false
}

func autoDeployWebhookAuthHint() string {
	return "GitHub: X-Hub-Signature-256, GitLab: X-Gitlab-Token, Gitea: X-Gitea-Signature, fallback: X-Webhook-Token or query secret"
}

func summarizeAuditMetadata(metadata string) string {
	metadata = strings.TrimSpace(metadata)
	if metadata == "" || metadata == "{}" || metadata == "null" {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(metadata), &payload); err != nil {
		return metadata
	}
	keys := []string{"provider", "auth_mode", "branch", "incoming_branch", "reason", "error", "action"}
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			text := strings.TrimSpace(fmt.Sprint(value))
			if text != "" {
				parts = append(parts, key+": "+text)
			}
		}
	}
	if len(parts) == 0 {
		return metadata
	}
	return strings.Join(parts, " | ")
}

func sanitizeSubdomainLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.ReplaceAll(label, "_", "-")
	label = strings.ReplaceAll(label, ".", "-")
	buffer := make([]rune, 0, len(label))
	lastHyphen := false
	for _, ch := range label {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			buffer = append(buffer, ch)
			lastHyphen = false
		case ch == '-':
			if len(buffer) == 0 || lastHyphen {
				continue
			}
			buffer = append(buffer, ch)
			lastHyphen = true
		}
	}
	cleaned := strings.Trim(string(buffer), "-")
	return cleaned
}

func subdomainConfigName(siteName string, fullDomain string) string {
	name := sanitizeSubdomainLabel(siteName + "-" + fullDomain)
	if name == "" {
		return "subdomain-site"
	}
	if len(name) > 63 {
		name = strings.Trim(name[:63], "-")
	}
	if len(name) < 2 || name[0] < 'a' || name[0] > 'z' {
		name = "s" + name
	}
	return name
}

func buildSiteSubdomain(site domain.ManagedSite, label string, mode string, upstreamURL string, phpVersion string, rootDirectory string) (domain.SiteSubdomain, system.SiteSpec, error) {
	label = sanitizeSubdomainLabel(label)
	if label == "" {
		return domain.SiteSubdomain{}, system.SiteSpec{}, errors.New("Subdomain label is required.")
	}
	fullDomain := label + "." + strings.TrimSpace(site.DomainName)
	mode = firstNonEmpty(strings.TrimSpace(mode), "reverse_proxy")
	rootDirectory = strings.TrimSpace(rootDirectory)
	if rootDirectory == "" {
		rootDirectory = filepath.Join(site.RootDirectory, "subdomains", label)
	}
	upstreamURL = strings.TrimSpace(upstreamURL)
	phpVersion = strings.TrimSpace(phpVersion)
	spec := system.SiteSpec{
		Name:           subdomainConfigName(site.Name, fullDomain),
		OwnerLinuxUser: site.OwnerLinuxUser,
		Domain:         fullDomain,
		Mode:           mode,
		RootDirectory:  rootDirectory,
		UpstreamURL:    upstreamURL,
		PHPVersion:     phpVersion,
	}
	record := domain.SiteSubdomain{
		SiteID:        site.ID,
		Subdomain:     label,
		FullDomain:    fullDomain,
		Runtime:       mode,
		UpstreamURL:   upstreamURL,
		PHPVersion:    phpVersion,
		RootDirectory: rootDirectory,
	}
	return record, spec, nil
}

func (a *App) handleSiteDeployWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	siteName := strings.TrimSpace(r.URL.Query().Get("site"))
	if siteName == "" {
		http.Error(w, "missing site", http.StatusBadRequest)
		return
	}
	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return
	}
	if !site.AutoDeployEnabled || site.AutoDeploySecret == "" {
		a.recordAudit(r.Context(), "deploy.webhook", site.Name, "failure", map[string]any{"reason": "auto_deploy_disabled"})
		http.Error(w, "auto deploy disabled", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	authMode, ok := verifyWebhookSecret(r, body, site.AutoDeploySecret)
	if !ok {
		a.recordAudit(r.Context(), "deploy.webhook", site.Name, "failure", map[string]any{"reason": "invalid_secret", "auth_mode": authMode})
		http.Error(w, "invalid secret", http.StatusForbidden)
		return
	}
	incomingBranch := buildWebhookBranch(body)
	provider := firstNonEmpty(strings.TrimSpace(r.Header.Get("X-GitHub-Event")), strings.TrimSpace(r.Header.Get("X-Gitlab-Event")), strings.TrimSpace(r.Header.Get("X-Gitea-Event")), "generic")
	configuredBranch := firstNonEmpty(site.AutoDeployBranch, "main")
	if incomingBranch != "" && configuredBranch != "" && incomingBranch != configuredBranch {
		a.recordAudit(r.Context(), "deploy.webhook", site.Name, "ignored", map[string]any{"reason": "branch_mismatch", "incoming_branch": incomingBranch, "branch": configuredBranch, "provider": provider, "auth_mode": authMode})
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "ignored", "reason": "branch_mismatch", "branch": incomingBranch})
		return
	}
	repositoryStatus, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser})
	if inspectErr != nil || strings.TrimSpace(repositoryStatus.RemoteURL) == "" {
		a.recordAudit(r.Context(), "deploy.webhook", site.Name, "failure", map[string]any{"reason": "repository_not_ready", "provider": provider, "auth_mode": authMode})
		http.Error(w, "site repository is not ready for auto deploy", http.StatusPreconditionFailed)
		return
	}
	a.recordAudit(r.Context(), "deploy.webhook", site.Name, "queued", map[string]any{"branch": configuredBranch, "incoming_branch": incomingBranch, "provider": provider, "auth_mode": authMode})
	go func(site domain.ManagedSite, repositoryURL string, branch string) {
		ctx := context.Background()
		result, deployErr := a.deploys.Deploy(system.DeploySpec{
			RepositoryURL:     repositoryURL,
			Branch:            branch,
			TargetDirectory:   site.RootDirectory,
			RunAsUser:         site.OwnerLinuxUser,
			PostDeployCommand: strings.TrimSpace(site.AutoDeployCommand),
		})
		if deployErr != nil {
			a.recordAudit(ctx, "deploy.webhook", site.Name, "failure", map[string]any{"branch": branch, "error": deployErr.Error(), "provider": provider, "auth_mode": authMode})
			_ = sendAutoDeployResultEmail(a.cfg, site, branch, domain.DeploymentRelease{RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser, Action: "deploy", Status: "failure", Output: ""}, deployErr)
			return
		}
		if a.store != nil {
			_ = a.store.CreateDeployment(ctx, domain.Deployment{SiteID: site.ID, RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser, LastStatus: "success", LastOutput: result.Output})
			_ = a.store.CreateDeploymentRelease(ctx, domain.DeploymentRelease{RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser, Action: result.Action, Status: "success", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output})
		}
		metadata := map[string]any{"branch": branch, "action": result.Action, "provider": provider, "auth_mode": authMode}
		if incomingBranch != "" {
			metadata["incoming_branch"] = incomingBranch
		}
		a.recordAudit(ctx, "deploy.webhook", site.Name, "success", metadata)
		_ = sendAutoDeployResultEmail(a.cfg, site, branch, domain.DeploymentRelease{RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser, Action: result.Action, Status: "success", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output}, nil)
	}(site, repositoryStatus.RemoteURL, configuredBranch)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "queued", "site": site.Name, "branch": configuredBranch})
}

func (a *App) handlePlaceholder(title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.render(r.Context(), w, r.URL.Path, "placeholder.html", TemplateData{
			Title:          title,
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			Alerts: []string{
				title + " module is scaffolded and ready for the next implementation slice.",
			},
		})
	}
}

func (a *App) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, listErr := a.users.ListLinuxUsers()
	if listErr != nil {
		users = nil
	}

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{
			Title:          "Users",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{
			Title:          "Users",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   "The submitted user form could not be parsed.",
		})
		return
	}

	if r.FormValue("user_action") == "delete" {
		a.handleUserDelete(w, r, users)
		return
	}

	username := r.FormValue("username")
	createHome := r.FormValue("create_home") == "1"
	if err := a.users.CreateLinuxUser(username, createHome); err != nil {
		a.recordAudit(r.Context(), "user.create", username, "failure", map[string]any{"create_home": createHome, "error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidUsername) {
			message = "Username format is invalid for Ubuntu user creation."
		}
		if errors.Is(err, system.ErrUserExists) {
			message = "That Linux user already exists on the host."
		}
		a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{
			Title:          "Users",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   message,
		})
		return
	}

	updatedUsers, _ := a.users.ListLinuxUsers()
	a.recordAudit(r.Context(), "user.create", username, "success", map[string]any{"create_home": createHome})
	a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{
		Title:          "Users",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     updatedUsers,
		SuccessMessage: "Linux user was created successfully.",
	})
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request, users []system.LinuxUser) {
	username := r.FormValue("delete_username")
	removeHome := r.FormValue("remove_home") == "1"
	if err := a.users.DeleteLinuxUser(username, removeHome); err != nil {
		a.recordAudit(r.Context(), "user.delete", username, "failure", map[string]any{"remove_home": removeHome, "error": err.Error()})
		message := err.Error()
		switch {
		case errors.Is(err, system.ErrInvalidUsername):
			message = "Linux username format is invalid."
		case errors.Is(err, system.ErrUserNotFound):
			message = "Linux user could not be found."
		case errors.Is(err, system.ErrProtectedUser):
			message = "This Linux user is protected and cannot be deleted from the panel."
		}
		a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{
			Title:          "Users",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   message,
		})
		return
	}

	updatedUsers, _ := a.users.ListLinuxUsers()
	a.recordAudit(r.Context(), "user.delete", username, "success", map[string]any{"remove_home": removeHome})
	a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{
		Title:          "Users",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     updatedUsers,
		SuccessMessage: "Linux user was deleted successfully.",
	})
}

func (a *App) handleDatabases(w http.ResponseWriter, r *http.Request) {
	entries, listErr := a.databases.ListDatabaseAccess()
	if listErr != nil {
		entries = nil
	}

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{
			Title:          "Databases",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			DatabaseAccess: entries,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.databases == nil {
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{
			Title:          "Databases",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			DatabaseAccess: entries,
			RequestError:   "MySQL admin provisioning is not configured yet.",
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{
			Title:          "Databases",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			DatabaseAccess: entries,
			RequestError:   "The submitted database form could not be parsed.",
		})
		return
	}

	switch r.FormValue("database_action") {
	case "rotate_admin_password":
		a.handleDatabaseAdminPasswordRotation(w, r, entries)
		return
	case "delete_access":
		a.handleDatabaseDelete(w, r, entries)
		return
	case "rotate_user_password":
		a.handleDatabaseUserPasswordRotation(w, r, entries)
		return
	}

	databaseName := r.FormValue("database_name")
	databaseUser := r.FormValue("database_user")
	databasePassword := r.FormValue("database_password")
	generated := false
	if databasePassword == "" {
		secret, err := randomPassword(24)
		if err != nil {
			http.Error(w, "password generation failed", http.StatusInternalServerError)
			return
		}
		databasePassword = secret
		generated = true
	}

	if err := a.databases.ProvisionDatabase(databaseName, databaseUser, databasePassword); err != nil {
		a.recordAudit(r.Context(), "database.provision", databaseName, "failure", map[string]any{"database_user": databaseUser, "error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidDatabaseName) {
			message = "Database name format is invalid for MySQL provisioning."
		}
		if errors.Is(err, system.ErrInvalidUserName) {
			message = "MySQL username format is invalid."
		}
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{
			Title:          "Databases",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			DatabaseAccess: entries,
			RequestError:   message,
		})
		return
	}

	a.recordAudit(r.Context(), "database.provision", databaseName, "success", map[string]any{"database_user": databaseUser})
	updatedEntries, _ := a.databases.ListDatabaseAccess()
	data := TemplateData{
		Title:          "Databases",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		DatabaseAccess: updatedEntries,
		SuccessMessage: "Database and MySQL user were provisioned successfully.",
	}
	if generated {
		data.GeneratedSecret = databasePassword
	}
	a.render(r.Context(), w, r.URL.Path, "databases.html", data)
}

func (a *App) handleDatabaseAdminPasswordRotation(w http.ResponseWriter, r *http.Request, entries []system.DatabaseAccess) {
	adminPassword := r.FormValue("admin_password")
	generated := false
	if adminPassword == "" {
		secret, err := randomPassword(24)
		if err != nil {
			http.Error(w, "password generation failed", http.StatusInternalServerError)
			return
		}
		adminPassword = secret
		generated = true
	}

	if err := a.databases.RotateAdminPassword(adminPassword); err != nil {
		a.recordAudit(r.Context(), "mysql.admin_password.rotate", a.cfg.MySQLAdminDefaultsFile, "failure", map[string]any{"error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidPassword) {
			message = "MySQL admin password cannot be empty."
		}
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{
			Title:          "Databases",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			DatabaseAccess: entries,
			RequestError:   message,
		})
		return
	}

	a.recordAudit(r.Context(), "mysql.admin_password.rotate", a.cfg.MySQLAdminDefaultsFile, "success", nil)
	data := TemplateData{
		Title:          "Databases",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		DatabaseAccess: entries,
		SuccessMessage: "MySQL admin password was rotated successfully.",
	}
	if generated {
		data.GeneratedSecret = adminPassword
	}
	a.render(r.Context(), w, r.URL.Path, "databases.html", data)
}

func (a *App) handleDatabaseDelete(w http.ResponseWriter, r *http.Request, entries []system.DatabaseAccess) {
	databaseName := r.FormValue("delete_database_name")
	databaseUser := r.FormValue("delete_database_user")
	databaseHost := r.FormValue("delete_database_host")
	dropDatabase := r.FormValue("drop_database") == "1"

	if err := a.databases.DeleteDatabaseAccess(databaseName, databaseUser, databaseHost, dropDatabase); err != nil {
		a.recordAudit(r.Context(), "database.delete", databaseName, "failure", map[string]any{"database_user": databaseUser, "database_host": databaseHost, "drop_database": dropDatabase, "error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidDatabaseName) {
			message = "Database name format is invalid."
		}
		if errors.Is(err, system.ErrInvalidUserName) {
			message = "MySQL username format is invalid."
		}
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{Title: "Databases", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), DatabaseAccess: entries, RequestError: message})
		return
	}

	updatedEntries, _ := a.databases.ListDatabaseAccess()
	a.recordAudit(r.Context(), "database.delete", databaseName, "success", map[string]any{"database_user": databaseUser, "database_host": databaseHost, "drop_database": dropDatabase})
	a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{Title: "Databases", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), DatabaseAccess: updatedEntries, SuccessMessage: "Database access was deleted successfully."})
}

func (a *App) handleDatabaseUserPasswordRotation(w http.ResponseWriter, r *http.Request, entries []system.DatabaseAccess) {
	databaseUser := r.FormValue("rotate_database_user")
	databaseHost := r.FormValue("rotate_database_host")
	databasePassword := r.FormValue("rotate_database_password")
	generated := false
	if databasePassword == "" {
		secret, err := randomPassword(24)
		if err != nil {
			http.Error(w, "password generation failed", http.StatusInternalServerError)
			return
		}
		databasePassword = secret
		generated = true
	}

	if err := a.databases.RotateUserPassword(databaseUser, databaseHost, databasePassword); err != nil {
		a.recordAudit(r.Context(), "database.rotate_user_password", databaseUser, "failure", map[string]any{"database_host": databaseHost, "error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidUserName) {
			message = "MySQL username format is invalid."
		}
		if errors.Is(err, system.ErrInvalidPassword) {
			message = "Database user password cannot be empty."
		}
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{Title: "Databases", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), DatabaseAccess: entries, RequestError: message})
		return
	}

	a.recordAudit(r.Context(), "database.rotate_user_password", databaseUser, "success", map[string]any{"database_host": databaseHost})
	data := TemplateData{Title: "Databases", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), DatabaseAccess: entries, SuccessMessage: "Database user password was updated successfully."}
	if generated {
		data.GeneratedSecret = databasePassword
	}
	data.DatabaseAccess, _ = a.databases.ListDatabaseAccess()
	a.render(r.Context(), w, r.URL.Path, "databases.html", data)
}

func (a *App) handleDatabaseDetails(w http.ResponseWriter, r *http.Request) {
	entries, listErr := a.databases.ListDatabaseAccess()
	if listErr != nil {
		entries = nil
	}
	if a.databases == nil {
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{
			Title:          "Databases",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			DatabaseAccess: entries,
			RequestError:   "MySQL admin provisioning is not configured yet.",
		})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	databaseName := strings.TrimSpace(r.URL.Query().Get("name"))
	selectedTable := strings.TrimSpace(r.URL.Query().Get("table"))
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		databaseName = strings.TrimSpace(r.FormValue("database_name"))
		selectedTable = strings.TrimSpace(r.FormValue("selected_table"))
	}
	if databaseName == "" {
		http.Redirect(w, r, "/databases", http.StatusSeeOther)
		return
	}

	details, detailErr := a.databases.InspectDatabase(system.DatabaseInspectSpec{DatabaseName: databaseName, TableName: selectedTable, Limit: 25})
	if detailErr != nil && r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "databases.html", TemplateData{
			Title:          "Databases",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			DatabaseAccess: entries,
			RequestError:   databaseDetailErrorMessage(detailErr),
		})
		return
	}

	data := TemplateData{}
	if r.Method == http.MethodPost {
		action := r.FormValue("database_details_action")
		switch action {
		case "restore":
			tempPath, restoreSQL, err := writeDatabaseRestoreTempFile(r)
			data.DatabaseRestoreSQL = restoreSQL
			if err != nil {
				data.RequestError = err.Error()
				break
			}
			defer os.Remove(tempPath)
			output, restoreErr := a.databases.RestoreDatabase(databaseName, tempPath)
			data.CommandOutput = output
			if restoreErr != nil {
				data.RequestError = databaseDetailErrorMessage(restoreErr)
				a.recordAudit(r.Context(), "database.restore", databaseName, "failure", map[string]any{"error": restoreErr.Error()})
				break
			}
			a.recordAudit(r.Context(), "database.restore", databaseName, "success", nil)
			data.SuccessMessage = "Database restore completed successfully."
			data.ResultPath = tempPath
		case "preview":
			selectedTable = strings.TrimSpace(r.FormValue("selected_table"))
		default:
			data.RequestError = "Invalid database details action."
		}
	}

	details, detailErr = a.databases.InspectDatabase(system.DatabaseInspectSpec{DatabaseName: databaseName, TableName: selectedTable, Limit: 25})
	if data.RequestError == "" && detailErr != nil {
		data.RequestError = databaseDetailErrorMessage(detailErr)
	}
	data.Title = databaseName + " details"
	data.DatabaseStatus = a.databaseStatus(r.Context())
	data.Metrics = a.metrics.Snapshot()
	data.DatabaseAccess = entries
	data.DatabaseDetails = details
	data.SelectedDatabaseEntries = filterDatabaseEntries(entries, databaseName)
	a.render(r.Context(), w, r.URL.Path, "database_details.html", data)
}

func writeDatabaseRestoreTempFile(r *http.Request) (string, string, error) {
	const maxRestoreBytes = 8 << 20
	sqlContent := r.FormValue("restore_sql")
	if strings.TrimSpace(sqlContent) == "" {
		file, _, err := r.FormFile("restore_file")
		if err != nil {
			return "", "", errors.New("Provide SQL content or upload a .sql file to restore.")
		}
		defer file.Close()
		content, err := io.ReadAll(io.LimitReader(file, maxRestoreBytes+1))
		if err != nil {
			return "", "", err
		}
		if len(content) > maxRestoreBytes {
			return "", "", errors.New("Restore file is too large. Maximum supported size is 8 MB.")
		}
		sqlContent = string(content)
	}
	if strings.TrimSpace(sqlContent) == "" {
		return "", "", errors.New("Restore content cannot be empty.")
	}
	if len(sqlContent) > maxRestoreBytes {
		return "", sqlContent, errors.New("Restore SQL is too large. Maximum supported size is 8 MB.")
	}
	tempFile, err := os.CreateTemp("", "ssc-db-restore-*.sql")
	if err != nil {
		return "", sqlContent, err
	}
	defer tempFile.Close()
	if _, err := tempFile.WriteString(sqlContent); err != nil {
		return "", sqlContent, err
	}
	return tempFile.Name(), sqlContent, nil
}

func filterDatabaseEntries(entries []system.DatabaseAccess, databaseName string) []system.DatabaseAccess {
	filtered := make([]system.DatabaseAccess, 0)
	for _, entry := range entries {
		if entry.DatabaseName != databaseName {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func databaseDetailErrorMessage(err error) string {
	message := err.Error()
	switch {
	case errors.Is(err, system.ErrInvalidDatabaseName):
		message = "Database name format is invalid."
	case errors.Is(err, system.ErrInvalidTableName):
		message = "Selected table name is invalid."
	case errors.Is(err, system.ErrInvalidRestorePath):
		message = "Restore file path is invalid."
	}
	return message
}

func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	users := a.listLinuxUsers()
	sites := a.listManagedSites(r)
	versions := a.listPHPVersions()

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   "The submitted site form could not be parsed.",
		})
		return
	}

	if r.FormValue("site_action") == "tls" {
		a.handleSiteTLS(w, r, users, sites, versions)
		return
	}
	if r.FormValue("site_action") == "delete" {
		a.handleSiteDelete(w, r, users, sites, versions)
		return
	}

	spec := system.SiteSpec{
		Name:           r.FormValue("site_name"),
		OwnerLinuxUser: r.FormValue("owner_linux_user"),
		Domain:         r.FormValue("domain"),
		Mode:           r.FormValue("mode"),
		UpstreamURL:    r.FormValue("upstream_url"),
		PHPVersion:     r.FormValue("php_version"),
	}

	rootDirectory, rootErr := buildManagedSiteRootDirectory(users, spec.OwnerLinuxUser, spec.Name)
	if rootErr != nil {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   rootErr.Error(),
		})
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

	configPath, err := a.nginx.ApplySite(spec)
	if err != nil {
		a.recordAudit(r.Context(), "nginx.apply_site", spec.Name, "failure", map[string]any{"domain": spec.Domain, "mode": spec.Mode, "error": err.Error()})
		message := err.Error()
		switch {
		case errors.Is(err, system.ErrInvalidSiteName):
			message = "Site name format is invalid. Use lowercase letters, numbers, and hyphens."
		case errors.Is(err, system.ErrInvalidUsername):
			message = "Owner Linux user is required and must be valid."
		case errors.Is(err, system.ErrUserNotFound):
			message = "Selected Linux user could not be found on the host."
		case errors.Is(err, system.ErrInvalidDomain):
			message = "Domain format is invalid."
		case errors.Is(err, system.ErrInvalidMode):
			message = "Site mode is invalid."
		case errors.Is(err, system.ErrInvalidUpstream):
			message = "Reverse proxy upstream is invalid."
		case errors.Is(err, system.ErrInvalidRootDirectory):
			message = "Root directory must be an absolute path for static or PHP sites."
		case errors.Is(err, system.ErrInvalidPHPVersion):
			message = "PHP version must look like 8.2 or 8.3."
		}
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   message,
		})
		return
	}

	if a.store != nil {
		_ = a.store.CreateManagedSite(r.Context(), domain.ManagedSite{
			Name:            spec.Name,
			OwnerLinuxUser:  spec.OwnerLinuxUser,
			DomainName:      spec.Domain,
			RootDirectory:   spec.RootDirectory,
			Runtime:         spec.Mode,
			UpstreamURL:     spec.UpstreamURL,
			PHPVersion:      spec.PHPVersion,
			NginxConfigPath: configPath,
		})
	}

	a.recordAudit(r.Context(), "nginx.apply_site", spec.Name, "success", map[string]any{"domain": spec.Domain, "mode": spec.Mode, "config_path": configPath})
	sites = a.listManagedSites(r)
	a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
		Title:          "Sites",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     users,
		ManagedSites:   sites,
		PHPVersions:    versions,
		SuccessMessage: "Nginx site was applied, validated, and reloaded successfully.",
		ResultPath:     configPath,
	})
}

func buildManagedSiteRootDirectory(users []system.LinuxUser, ownerLinuxUser string, siteName string) (string, error) {
	ownerLinuxUser = strings.TrimSpace(ownerLinuxUser)
	siteName = strings.TrimSpace(siteName)
	if ownerLinuxUser == "" {
		return "", errors.New("Select an owner Linux user to create the site root directory.")
	}
	if siteName == "" {
		return "", errors.New("Site name is required to build the root directory.")
	}

	for _, user := range users {
		if user.Username != ownerLinuxUser {
			continue
		}
		return filepath.Join("/var/www", ownerLinuxUser, siteName), nil
	}

	return "", errors.New("Selected Linux user home directory could not be resolved.")
}

func (a *App) handleSiteTLS(w http.ResponseWriter, r *http.Request, users []system.LinuxUser, sites []domain.ManagedSite, versions []string) {
	request := system.TLSRequest{
		Domain:   r.FormValue("tls_domain"),
		Email:    r.FormValue("tls_email"),
		Redirect: r.FormValue("tls_redirect") == "1",
	}

	output, err := a.nginx.EnableTLS(request)
	if err != nil {
		a.recordAudit(r.Context(), "nginx.enable_tls", request.Domain, "failure", map[string]any{"email": request.Email, "error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidDomain) {
			message = "Domain format is invalid for TLS issuance."
		}
		if errors.Is(err, system.ErrInvalidEmail) {
			message = "Email format is invalid for Certbot."
		}
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   message,
			CommandOutput:  output,
		})
		return
	}

	a.recordAudit(r.Context(), "nginx.enable_tls", request.Domain, "success", map[string]any{"email": request.Email, "redirect": request.Redirect})
	a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
		Title:          "Sites",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     users,
		ManagedSites:   sites,
		PHPVersions:    versions,
		SuccessMessage: "TLS certificate was issued and Nginx was reloaded successfully.",
		CommandOutput:  output,
	})
}

func (a *App) handleSiteDelete(w http.ResponseWriter, r *http.Request, users []system.LinuxUser, sites []domain.ManagedSite, versions []string) {
	if a.store == nil {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   "Managed site storage is not configured yet. Set PANEL_DATABASE_DSN first.",
		})
		return
	}

	siteName := r.FormValue("delete_site_name")
	if r.FormValue("confirm_delete") != "1" {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   "Site deletion was not confirmed.",
		})
		return
	}

	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		a.recordAudit(r.Context(), "nginx.delete_site", siteName, "failure", map[string]any{"error": err.Error()})
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   "Managed site could not be found by that name.",
		})
		return
	}

	if err := a.nginx.DeleteSite(system.SiteRemoval{Name: site.Name, Domain: site.DomainName, RootDirectory: site.RootDirectory, ConfigPath: site.NginxConfigPath}); err != nil {
		a.recordAudit(r.Context(), "nginx.delete_site", site.Name, "failure", map[string]any{"config_path": site.NginxConfigPath, "root_directory": site.RootDirectory, "error": err.Error()})
		message := err.Error()
		switch {
		case errors.Is(err, system.ErrInvalidSiteName):
			message = "Site name format is invalid."
		case errors.Is(err, system.ErrUnsafeDeletePath):
			message = "Site root path is outside the allowed delete locations."
		case errors.Is(err, system.ErrInvalidRootDirectory):
			message = "Stored site directory or config path is invalid."
		}
		if refreshedSites := a.listManagedSites(r); refreshedSites != nil {
			sites = refreshedSites
		}
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   message,
		})
		return
	}

	if err := a.store.DeleteManagedSite(r.Context(), site.Name); err != nil {
		a.recordAudit(r.Context(), "nginx.delete_site", site.Name, "failure", map[string]any{"config_path": site.NginxConfigPath, "root_directory": site.RootDirectory, "error": err.Error(), "cleanup": "store"})
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   a.listManagedSites(r),
			PHPVersions:    versions,
			RequestError:   "Nginx site was deleted but the panel record could not be removed.",
		})
		return
	}

	a.recordAudit(r.Context(), "nginx.delete_site", site.Name, "success", map[string]any{"config_path": site.NginxConfigPath, "root_directory": site.RootDirectory})
	sites = a.listManagedSites(r)
	a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
		Title:          "Sites",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     users,
		ManagedSites:   sites,
		PHPVersions:    versions,
		SuccessMessage: "Site, Nginx configuration, and related directory were deleted successfully.",
	})
}

func (a *App) handleSiteDetails(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     a.listLinuxUsers(),
			ManagedSites:   a.listManagedSites(r),
			PHPVersions:    a.listPHPVersions(),
			RequestError:   "Managed site storage is not configured yet. Set PANEL_DATABASE_DSN first.",
		})
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	siteName := strings.TrimSpace(r.URL.Query().Get("name"))
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		siteName = strings.TrimSpace(r.FormValue("site_name"))
	}
	if siteName == "" {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}

	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     a.listLinuxUsers(),
			ManagedSites:   a.listManagedSites(r),
			PHPVersions:    a.listPHPVersions(),
			RequestError:   "Managed site could not be found by that name.",
		})
		return
	}

	repositoryStatus, statusErr := a.deploys.Inspect(system.RepositoryInspectSpec{
		TargetDirectory: site.RootDirectory,
		RunAsUser:       site.OwnerLinuxUser,
	})
	runtimeStatus, runtimeErr := a.runtime.Inspect(system.RuntimeInspectSpec{User: site.OwnerLinuxUser})
	branch := repositoryStatus.Branch
	if branch == "" {
		branch = "main"
	}
	repositoryURL := repositoryStatus.RemoteURL
	gitAuthStatus, gitAuthErr := a.gitAuth.Inspect(system.GitAuthInspectSpec{User: site.OwnerLinuxUser, SiteName: site.Name, RepositoryURL: repositoryURL})
	releases := a.listSiteDeploymentReleases(r, site.RootDirectory, site.OwnerLinuxUser)

	if r.Method == http.MethodGet {
		data := TemplateData{SiteDetailTab: firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tab")), "overview")}
		if statusErr != nil {
			data.RequestError = "Repository status could not be inspected: " + statusErr.Error()
		} else if runtimeErr != nil {
			data.RequestError = "Runtime status could not be inspected: " + runtimeErr.Error()
		} else if gitAuthErr != nil {
			data.RequestError = "Git auth status could not be inspected: " + gitAuthErr.Error()
		}
		a.renderSiteDetails(w, r, site, repositoryStatus, runtimeStatus, gitAuthStatus, releases, data)
		return
	}

	action := r.FormValue("details_action")
	if action == "" {
		a.renderSiteDetails(w, r, site, repositoryStatus, runtimeStatus, gitAuthStatus, releases, TemplateData{
			RequestError: "Invalid site details action.",
		})
		return
	}

	data := TemplateData{
		SiteDetailTab:       siteDetailTabForAction(action),
		GitRepositoryURL:    firstNonEmpty(strings.TrimSpace(r.FormValue("repository_url")), repositoryURL),
		GitBranch:           firstNonEmpty(strings.TrimSpace(r.FormValue("branch")), branch),
		GitPostDeployCommand: r.FormValue("post_deploy_command"),
		AutoDeployEnabled:  r.FormValue("auto_deploy_enabled") == "1",
		AutoDeployBranch:   strings.TrimSpace(r.FormValue("auto_deploy_branch")),
		AutoDeploySecret:   strings.TrimSpace(r.FormValue("auto_deploy_secret")),
		AutoDeployCommand:  r.FormValue("auto_deploy_command"),
		AutoDeployNotifyEmail: strings.TrimSpace(r.FormValue("auto_deploy_notify_email")),
		RuntimeNodeVersion:  strings.TrimSpace(r.FormValue("node_version")),
		PM2NodeVersion:      strings.TrimSpace(r.FormValue("pm2_node_version")),
		PM2ProcessName:      firstNonEmpty(strings.TrimSpace(r.FormValue("process_name")), site.Name),
		PM2ScriptPath:       strings.TrimSpace(r.FormValue("script_path")),
		PM2Arguments:        strings.TrimSpace(r.FormValue("process_arguments")),
		SubdomainLabel:      strings.TrimSpace(r.FormValue("subdomain_label")),
		SubdomainMode:       firstNonEmpty(strings.TrimSpace(r.FormValue("subdomain_mode")), "reverse_proxy"),
		SubdomainUpstreamURL: strings.TrimSpace(r.FormValue("subdomain_upstream_url")),
		SubdomainPHPVersion: strings.TrimSpace(r.FormValue("subdomain_php_version")),
		SubdomainRootDirectory: strings.TrimSpace(r.FormValue("subdomain_root_directory")),
		SubdomainTLSEmail:   strings.TrimSpace(r.FormValue("subdomain_tls_email")),
		RuntimeCommandName:  strings.TrimSpace(r.FormValue("runtime_command_name")),
		RuntimeCommandNodeVersion: strings.TrimSpace(r.FormValue("runtime_command_node_version")),
		RuntimeCommandBody:  r.FormValue("runtime_command_body"),
		GitCredentialProtocol: firstNonEmpty(strings.TrimSpace(r.FormValue("credential_protocol")), firstNonEmpty(gitAuthStatus.RepositoryProtocol, "https")),
		GitCredentialHost:   firstNonEmpty(strings.TrimSpace(r.FormValue("credential_host")), gitAuthStatus.RepositoryHost),
		GitCredentialUsername: strings.TrimSpace(r.FormValue("credential_username")),
	}
	if commandID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("runtime_command_id")), 10, 64); err == nil {
		data.RuntimeCommandID = commandID
	}
	if subdomainDeleteID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64); err == nil {
		data.SubdomainDeleteID = subdomainDeleteID
	}

	var output string
	var actionErr error
	var successMessage string

	switch action {
	case "sync_repository":
		if data.GitRepositoryURL == "" {
			data.RequestError = "Repository URL is required."
			break
		}
		spec := system.DeploySpec{
			RepositoryURL:     data.GitRepositoryURL,
			Branch:            data.GitBranch,
			TargetDirectory:   site.RootDirectory,
			RunAsUser:         site.OwnerLinuxUser,
			PostDeployCommand: data.GitPostDeployCommand,
		}
		wasGitRepo := repositoryStatus.IsGitRepo
		result, err := a.deploys.Deploy(spec)
		if err != nil {
			a.recordAudit(r.Context(), "deploy.site_sync", site.Name, "failure", map[string]any{"repository_url": spec.RepositoryURL, "branch": spec.Branch, "run_as_user": spec.RunAsUser, "target_directory": spec.TargetDirectory, "error": err.Error()})
			data.RequestError = deployErrorMessage(err)
			data.CommandOutput = result.Output
			break
		}
		if a.store != nil {
			_ = a.store.CreateDeployment(r.Context(), domain.Deployment{SiteID: site.ID, RepositoryURL: spec.RepositoryURL, BranchName: spec.Branch, TargetDirectory: spec.TargetDirectory, RunAsUser: spec.RunAsUser, LastStatus: "success", LastOutput: result.Output})
			_ = a.store.CreateDeploymentRelease(r.Context(), domain.DeploymentRelease{RepositoryURL: spec.RepositoryURL, BranchName: spec.Branch, TargetDirectory: spec.TargetDirectory, RunAsUser: spec.RunAsUser, Action: result.Action, Status: "success", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output})
		}
		a.recordAudit(r.Context(), "deploy.site_sync", site.Name, "success", map[string]any{"repository_url": spec.RepositoryURL, "branch": spec.Branch, "run_as_user": spec.RunAsUser, "target_directory": spec.TargetDirectory, "action": result.Action})
		output = result.Output
		data.CommandOutput = result.Output
		data.CommitSHA = result.CommitSHA
		data.PreviousCommitSHA = result.PreviousCommitSHA
		data.ResultPath = site.RootDirectory
		if wasGitRepo {
			successMessage = "Repository pulled for this site successfully."
		} else {
			successMessage = "Repository cloned into the site root successfully."
		}
	case "install_nvm":
		output, actionErr = a.runtime.InstallNVM(site.OwnerLinuxUser)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "runtime.install_nvm", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "runtime.install_nvm", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser})
		data.CommandOutput = output
		successMessage = "NVM was installed for the site owner successfully."
	case "install_node":
		output, actionErr = a.runtime.InstallNode(system.NodeInstallSpec{User: site.OwnerLinuxUser, Version: data.RuntimeNodeVersion, SetDefault: r.FormValue("set_default_node") == "1"})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "runtime.install_node", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "version": data.RuntimeNodeVersion, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "runtime.install_node", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser, "version": data.RuntimeNodeVersion})
		data.CommandOutput = output
		successMessage = "Node version was installed successfully for the site owner."
	case "install_pm2":
		output, actionErr = a.runtime.InstallPM2(system.PM2InstallSpec{User: site.OwnerLinuxUser, NodeVersion: data.PM2NodeVersion})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "runtime.install_pm2", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "node_version": data.PM2NodeVersion, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "runtime.install_pm2", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser, "node_version": data.PM2NodeVersion})
		data.CommandOutput = output
		successMessage = "PM2 was installed successfully for the site owner."
	case "start_pm2":
		output, actionErr = a.runtime.StartPM2(system.PM2StartSpec{User: site.OwnerLinuxUser, WorkingDirectory: site.RootDirectory, ProcessName: data.PM2ProcessName, ScriptPath: data.PM2ScriptPath, Arguments: data.PM2Arguments, NodeVersion: data.PM2NodeVersion})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "runtime.start_pm2", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "process_name": data.PM2ProcessName, "script_path": data.PM2ScriptPath, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "runtime.start_pm2", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser, "process_name": data.PM2ProcessName, "script_path": data.PM2ScriptPath})
		data.CommandOutput = output
		successMessage = "PM2 process was started for this site successfully."
	case "generate_deploy_key":
		var updatedStatus system.GitAuthStatus
		updatedStatus, output, actionErr = a.gitAuth.EnsureDeployKey(system.GitDeployKeySpec{User: site.OwnerLinuxUser, SiteName: site.Name, RepositoryURL: data.GitRepositoryURL})
		if actionErr != nil {
			data.RequestError = gitAuthErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "git_auth.ensure_deploy_key", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "error": actionErr.Error()})
			break
		}
		gitAuthStatus = updatedStatus
		a.recordAudit(r.Context(), "git_auth.ensure_deploy_key", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser})
		data.CommandOutput = output
		successMessage = "SSH deploy key is ready. Add the public key to your git provider and use the SSH repo URL."
	case "trust_git_host":
		output, actionErr = a.gitAuth.TrustHost(system.GitHostTrustSpec{User: site.OwnerLinuxUser, Host: data.GitCredentialHost})
		if actionErr != nil {
			data.RequestError = gitAuthErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "git_auth.trust_host", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "host": data.GitCredentialHost, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "git_auth.trust_host", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser, "host": data.GitCredentialHost})
		data.CommandOutput = output
		successMessage = "Git host was added to known_hosts successfully."
	case "store_git_credential":
		output, actionErr = a.gitAuth.StoreCredential(system.GitCredentialSpec{User: site.OwnerLinuxUser, Protocol: data.GitCredentialProtocol, Host: data.GitCredentialHost, Username: data.GitCredentialUsername, Password: r.FormValue("credential_password")})
		if actionErr != nil {
			data.RequestError = gitAuthErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "git_auth.store_credential", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "protocol": data.GitCredentialProtocol, "host": data.GitCredentialHost, "username": data.GitCredentialUsername, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "git_auth.store_credential", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser, "protocol": data.GitCredentialProtocol, "host": data.GitCredentialHost, "username": data.GitCredentialUsername})
		data.CommandOutput = output
		successMessage = "Git credentials were stored for private HTTPS access successfully."
	case "run_npm_script":
		scriptName := strings.TrimSpace(r.FormValue("script_name"))
		nodeVersion := strings.TrimSpace(r.FormValue("npm_script_node_version"))
		output, actionErr = a.runtime.RunNPMScript(system.NPMScriptSpec{
			User:             site.OwnerLinuxUser,
			WorkingDirectory: site.RootDirectory,
			ScriptName:       scriptName,
			NodeVersion:      nodeVersion,
		})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "runtime.run_npm_script", site.Name, "failure", map[string]any{"script": scriptName, "node_version": nodeVersion, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "runtime.run_npm_script", site.Name, "success", map[string]any{"script": scriptName, "node_version": nodeVersion})
		data.CommandOutput = output
		successMessage = "npm run " + scriptName + " completed successfully."
	case "enable_tls":
		tlsRequest := system.TLSRequest{
			Domain:   strings.TrimSpace(r.FormValue("tls_domain")),
			Email:    strings.TrimSpace(r.FormValue("tls_email")),
			Redirect: r.FormValue("tls_redirect") == "1",
		}
		output, actionErr = a.nginx.EnableTLS(tlsRequest)
		if actionErr != nil {
			message := actionErr.Error()
			if errors.Is(actionErr, system.ErrInvalidDomain) {
				message = "Domain format is invalid for TLS issuance."
			}
			if errors.Is(actionErr, system.ErrInvalidEmail) {
				message = "Email format is invalid for Certbot."
			}
			data.RequestError = message
			data.CommandOutput = output
			a.recordAudit(r.Context(), "nginx.enable_tls", tlsRequest.Domain, "failure", map[string]any{"email": tlsRequest.Email, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "nginx.enable_tls", tlsRequest.Domain, "success", map[string]any{"email": tlsRequest.Email, "redirect": tlsRequest.Redirect})
		data.CommandOutput = output
		successMessage = "TLS certificate was issued and Nginx reloaded successfully."
	case "edit_env":
		envPath := filepath.Join(site.RootDirectory, ".env")
		if filepath.Clean(envPath) != filepath.Clean(site.RootDirectory)+"/.env" {
			data.RequestError = "Invalid .env file path."
			break
		}
		content := r.FormValue("env_content")
		_, actionErr = a.helper.Call(r.Context(), "files.write_env", map[string]string{
			"path":    envPath,
			"content": content,
			"owner":   site.OwnerLinuxUser,
		}, nil)
		if actionErr != nil {
			data.RequestError = "Could not write .env file: " + actionErr.Error()
			break
		}
		a.recordAudit(r.Context(), "site.edit_env", site.Name, "success", nil)
		successMessage = ".env file saved successfully."
	case "npm_install":
		nodeVersion := strings.TrimSpace(r.FormValue("npm_script_node_version"))
		ci := r.FormValue("npm_ci") == "1"
		output, actionErr = a.runtime.RunNPMInstall(system.NPMInstallSpec{
			User:             site.OwnerLinuxUser,
			WorkingDirectory: site.RootDirectory,
			NodeVersion:      nodeVersion,
			CI:               ci,
		})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			installCmd := "npm install"
			if ci {
				installCmd = "npm ci"
			}
			a.recordAudit(r.Context(), "runtime.npm_install", site.Name, "failure", map[string]any{"cmd": installCmd, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		installLabel := "npm install"
		if ci {
			installLabel = "npm ci"
		}
		a.recordAudit(r.Context(), "runtime.npm_install", site.Name, "success", map[string]any{"cmd": installLabel})
		successMessage = installLabel + " completed successfully."
	case "save_runtime_command":
		if strings.TrimSpace(data.RuntimeCommandName) == "" {
			data.RequestError = "Profile name is required."
			break
		}
		if strings.TrimSpace(data.RuntimeCommandBody) == "" {
			data.RequestError = "Custom command cannot be empty."
			break
		}
		if data.RuntimeCommandNodeVersion == "" {
			data.RuntimeCommandNodeVersion = runtimeStatus.DefaultNodeVersion
		}
		commandID, err := a.store.UpsertSiteRuntimeCommand(r.Context(), domain.SiteRuntimeCommand{
			ID:          data.RuntimeCommandID,
			SiteID:      site.ID,
			Name:        data.RuntimeCommandName,
			CommandBody: data.RuntimeCommandBody,
			NodeVersion: data.RuntimeCommandNodeVersion,
		})
		if err != nil {
			data.RequestError = "Could not save runtime command profile: " + err.Error()
			break
		}
		data.RuntimeCommandID = commandID
		a.recordAudit(r.Context(), "site.save_runtime_command", site.Name, "success", map[string]any{"profile": data.RuntimeCommandName, "command_id": commandID})
		successMessage = fmt.Sprintf("Runtime command profile \"%s\" saved.", data.RuntimeCommandName)
	case "delete_runtime_command":
		if data.RuntimeCommandID <= 0 {
			data.RequestError = "Select a saved profile to delete."
			break
		}
		if err := a.store.DeleteSiteRuntimeCommand(r.Context(), site.ID, data.RuntimeCommandID); err != nil {
			data.RequestError = "Could not delete runtime command profile: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.delete_runtime_command", site.Name, "success", map[string]any{"command_id": data.RuntimeCommandID, "profile": data.RuntimeCommandName})
		data.RuntimeCommandID = 0
		data.RuntimeCommandName = ""
		data.RuntimeCommandNodeVersion = runtimeStatus.DefaultNodeVersion
		data.RuntimeCommandBody = ""
		successMessage = "Runtime command profile deleted."
	case "save_auto_deploy":
		if data.AutoDeployBranch == "" {
			data.AutoDeployBranch = firstNonEmpty(branch, "main")
		}
		if data.AutoDeployEnabled && data.AutoDeploySecret == "" {
			secret, err := randomPassword(32)
			if err != nil {
				data.RequestError = "Could not generate auto deploy secret."
				break
			}
			data.AutoDeploySecret = secret
		}
		if err := a.store.UpdateManagedSiteAutoDeploy(r.Context(), site.Name, data.AutoDeployEnabled, data.AutoDeployBranch, data.AutoDeploySecret, data.AutoDeployCommand, data.AutoDeployNotifyEmail); err != nil {
			data.RequestError = "Could not save auto deploy settings: " + err.Error()
			break
		}
		site.AutoDeployEnabled = data.AutoDeployEnabled
		site.AutoDeployBranch = data.AutoDeployBranch
		site.AutoDeploySecret = data.AutoDeploySecret
		site.AutoDeployCommand = data.AutoDeployCommand
		site.AutoDeployNotifyEmail = data.AutoDeployNotifyEmail
		a.recordAudit(r.Context(), "site.auto_deploy.save", site.Name, "success", map[string]any{"enabled": data.AutoDeployEnabled, "branch": data.AutoDeployBranch})
		successMessage = "Auto deploy settings saved."
	case "rotate_auto_deploy_secret":
		secret, err := randomPassword(32)
		if err != nil {
			data.RequestError = "Could not rotate auto deploy secret."
			break
		}
		data.AutoDeploySecret = secret
		if data.AutoDeployBranch == "" {
			data.AutoDeployBranch = firstNonEmpty(site.AutoDeployBranch, branch, "main")
		}
		if err := a.store.UpdateManagedSiteAutoDeploy(r.Context(), site.Name, data.AutoDeployEnabled || site.AutoDeployEnabled, data.AutoDeployBranch, data.AutoDeploySecret, firstNonEmpty(data.AutoDeployCommand, site.AutoDeployCommand), firstNonEmpty(data.AutoDeployNotifyEmail, site.AutoDeployNotifyEmail)); err != nil {
			data.RequestError = "Could not rotate auto deploy secret: " + err.Error()
			break
		}
		site.AutoDeploySecret = data.AutoDeploySecret
		site.AutoDeployNotifyEmail = firstNonEmpty(data.AutoDeployNotifyEmail, site.AutoDeployNotifyEmail)
		a.recordAudit(r.Context(), "site.auto_deploy.rotate_secret", site.Name, "success", nil)
		successMessage = "Auto deploy secret rotated."
	case "add_subdomain":
		subdomainRecord, siteSpec, err := buildSiteSubdomain(site, data.SubdomainLabel, data.SubdomainMode, data.SubdomainUpstreamURL, data.SubdomainPHPVersion, data.SubdomainRootDirectory)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		configPath, err := a.nginx.ApplySite(siteSpec)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		subdomainRecord.NginxConfigPath = configPath
		if err := a.store.CreateSiteSubdomain(r.Context(), subdomainRecord); err != nil {
			data.RequestError = "Subdomain was applied in Nginx but could not be stored: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.create", subdomainRecord.FullDomain, "success", map[string]any{"mode": subdomainRecord.Runtime})
		successMessage = "Subdomain applied successfully."
		data.SubdomainLabel = ""
		data.SubdomainUpstreamURL = ""
		data.SubdomainPHPVersion = ""
	case "delete_subdomain":
		subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if err != nil {
			data.RequestError = "Could not load subdomains: " + err.Error()
			break
		}
		var selected *domain.SiteSubdomain
		for index := range subdomains {
			if subdomains[index].ID == data.SubdomainDeleteID {
				selected = &subdomains[index]
				break
			}
		}
		if selected == nil {
			data.RequestError = "Subdomain record could not be found."
			break
		}
		if err := a.nginx.DeleteSite(system.SiteRemoval{Name: subdomainConfigName(site.Name, selected.FullDomain), Domain: selected.FullDomain, RootDirectory: selected.RootDirectory, ConfigPath: selected.NginxConfigPath}); err != nil {
			data.RequestError = "Could not delete subdomain from Nginx: " + err.Error()
			break
		}
		if err := a.store.DeleteSiteSubdomain(r.Context(), site.ID, selected.ID); err != nil {
			data.RequestError = "Subdomain Nginx config was removed but panel record could not be deleted: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.delete", selected.FullDomain, "success", nil)
		successMessage = "Subdomain deleted successfully."
	case "enable_subdomain_tls":
		subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if err != nil {
			data.RequestError = "Could not load subdomains: " + err.Error()
			break
		}
		var selected *domain.SiteSubdomain
		for index := range subdomains {
			if subdomains[index].ID == data.SubdomainDeleteID {
				selected = &subdomains[index]
				break
			}
		}
		if selected == nil {
			data.RequestError = "Subdomain record could not be found."
			break
		}
		if data.SubdomainTLSEmail == "" {
			data.RequestError = "TLS email is required for the subdomain certificate."
			break
		}
		output, actionErr = a.nginx.EnableTLS(system.TLSRequest{Domain: selected.FullDomain, Email: data.SubdomainTLSEmail, Redirect: r.FormValue("subdomain_tls_redirect") == "1"})
		if actionErr != nil {
			data.RequestError = "Could not enable TLS for subdomain: " + actionErr.Error()
			data.CommandOutput = output
			a.recordAudit(r.Context(), "site.subdomain.enable_tls", selected.FullDomain, "failure", map[string]any{"email": data.SubdomainTLSEmail, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.subdomain.enable_tls", selected.FullDomain, "success", map[string]any{"email": data.SubdomainTLSEmail})
		successMessage = "Subdomain TLS enabled successfully."
	case "restart_pm2":
		processName := strings.TrimSpace(r.FormValue("process_name"))
		output, actionErr = a.pm2.Restart(site.OwnerLinuxUser, processName)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "pm2.restart", site.Name, "failure", map[string]any{"process": processName, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "pm2.restart", site.Name, "success", map[string]any{"process": processName})
		data.CommandOutput = output
		successMessage = "PM2 process restarted successfully."
	case "reload_pm2":
		processName := strings.TrimSpace(r.FormValue("process_name"))
		output, actionErr = a.pm2.Reload(site.OwnerLinuxUser, processName)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "pm2.reload", site.Name, "failure", map[string]any{"process": processName, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "pm2.reload", site.Name, "success", map[string]any{"process": processName})
		data.CommandOutput = output
		successMessage = "PM2 process reloaded successfully."
	case "stop_pm2":
		processName := strings.TrimSpace(r.FormValue("process_name"))
		output, actionErr = a.pm2.Stop(site.OwnerLinuxUser, processName)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "pm2.stop", site.Name, "failure", map[string]any{"process": processName, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "pm2.stop", site.Name, "success", map[string]any{"process": processName})
		data.CommandOutput = output
		successMessage = "PM2 process stopped successfully."
	case "assign_database":
		dbName := strings.TrimSpace(r.FormValue("assigned_database"))
		if err := a.store.UpdateManagedSiteDatabaseName(r.Context(), site.Name, dbName); err != nil {
			data.RequestError = "Could not assign database: " + err.Error()
			break
		}
		site.DatabaseName = dbName
		if dbName == "" {
			successMessage = "Database assignment cleared."
		} else {
			successMessage = "Database \"" + dbName + "\" assigned to site."
		}
		a.recordAudit(r.Context(), "site.assign_database", site.Name, "success", map[string]any{"database": dbName})
	case "assign_linux_user":
		newOwner := strings.TrimSpace(r.FormValue("assigned_linux_user"))
		if newOwner == "" {
			data.RequestError = "Linux user cannot be empty."
			break
		}
		if err := a.store.UpdateManagedSiteOwnerLinuxUser(r.Context(), site.Name, newOwner); err != nil {
			data.RequestError = "Could not assign Linux user: " + err.Error()
			break
		}
		site.OwnerLinuxUser = newOwner
		successMessage = "Linux user reassigned to \"" + newOwner + "\"."
		a.recordAudit(r.Context(), "site.assign_linux_user", site.Name, "success", map[string]any{"owner": newOwner})
	default:
		data.RequestError = "Invalid site details action."
	}

	repositoryStatus, statusErr = a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: site.RootDirectory, RunAsUser: site.OwnerLinuxUser})
	runtimeStatus, runtimeErr = a.runtime.Inspect(system.RuntimeInspectSpec{User: site.OwnerLinuxUser})
	repositoryURL = firstNonEmpty(data.GitRepositoryURL, repositoryStatus.RemoteURL)
	gitAuthStatus, gitAuthErr = a.gitAuth.Inspect(system.GitAuthInspectSpec{User: site.OwnerLinuxUser, SiteName: site.Name, RepositoryURL: repositoryURL})
	releases = a.listSiteDeploymentReleases(r, site.RootDirectory, site.OwnerLinuxUser)
	if successMessage != "" {
		data.SuccessMessage = successMessage
	}
	if data.RequestError == "" {
		if statusErr != nil {
			data.RequestError = "Repository status refreshed with an error: " + statusErr.Error()
		} else if runtimeErr != nil {
			data.RequestError = "Runtime status refreshed with an error: " + runtimeErr.Error()
		} else if gitAuthErr != nil {
			data.RequestError = "Git auth status refreshed with an error: " + gitAuthErr.Error()
		}
	}
	a.renderSiteDetails(w, r, site, repositoryStatus, runtimeStatus, gitAuthStatus, releases, data)
}

func (a *App) handleDeploys(w http.ResponseWriter, r *http.Request) {
	users := a.listLinuxUsers()
	releases := []domain.DeploymentRelease{}
	if a.store != nil {
		if entries, err := a.store.ListDeploymentReleases(r.Context(), 12); err == nil {
			releases = entries
		}
	}

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
			Title:          "Deploys",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			DeploymentReleases: releases,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
			Title:          "Deploys",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   "The submitted deploy form could not be parsed.",
			DeploymentReleases: releases,
		})
		return
	}

	mode := r.FormValue("deploy_mode")
	if mode == "rollback" {
		a.handleDeployRollback(w, r, users, releases)
		return
	}

	spec := system.DeploySpec{
		RepositoryURL:     r.FormValue("repository_url"),
		Branch:            r.FormValue("branch"),
		TargetDirectory:   r.FormValue("target_directory"),
		RunAsUser:         r.FormValue("run_as_user"),
		PostDeployCommand: r.FormValue("post_deploy_command"),
	}

	result, err := a.deploys.Deploy(spec)
	if err != nil {
		a.recordAudit(r.Context(), "deploy.run", spec.TargetDirectory, "failure", map[string]any{"repository_url": spec.RepositoryURL, "run_as_user": spec.RunAsUser, "error": err.Error()})
		message := err.Error()
		switch {
		case errors.Is(err, system.ErrInvalidRepoURL):
			message = "Repository URL is invalid. Use an https or git@ style URL."
		case errors.Is(err, system.ErrInvalidBranch):
			message = "Branch name is invalid."
		case errors.Is(err, system.ErrInvalidTargetDirectory):
			message = "Target directory must be an absolute path."
		case errors.Is(err, system.ErrInvalidRunAsUser):
			message = "Run-as user is invalid for Ubuntu deployment."
		}
		a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
			Title:          "Deploys",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   message,
			CommandOutput:  result.Output,
			DeploymentReleases: releases,
		})
		return
	}

	if a.store != nil {
		branch := spec.Branch
		if branch == "" {
			branch = "main"
		}
		_ = a.store.CreateDeployment(r.Context(), domain.Deployment{
			RepositoryURL:  spec.RepositoryURL,
			BranchName:     branch,
			TargetDirectory: spec.TargetDirectory,
			RunAsUser:      spec.RunAsUser,
			LastStatus:     "success",
			LastOutput:     result.Output,
		})
		_ = a.store.CreateDeploymentRelease(r.Context(), domain.DeploymentRelease{
			RepositoryURL:     spec.RepositoryURL,
			BranchName:        branch,
			TargetDirectory:   spec.TargetDirectory,
			RunAsUser:         spec.RunAsUser,
			Action:            result.Action,
			Status:            "success",
			CommitSHA:         result.CommitSHA,
			PreviousCommitSHA: result.PreviousCommitSHA,
			Output:            result.Output,
		})
	}

	a.recordAudit(r.Context(), "deploy.run", spec.TargetDirectory, "success", map[string]any{"repository_url": spec.RepositoryURL, "run_as_user": spec.RunAsUser})
	if a.store != nil {
		if entries, err := a.store.ListDeploymentReleases(r.Context(), 12); err == nil {
			releases = entries
		}
	}
	a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
		Title:          "Deploys",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     users,
		SuccessMessage: "Repository deploy completed successfully.",
		ResultPath:     spec.TargetDirectory,
		CommandOutput:  result.Output,
		CommitSHA:      result.CommitSHA,
		PreviousCommitSHA: result.PreviousCommitSHA,
		DeploymentReleases: releases,
	})
}

func (a *App) handleDeployRollback(w http.ResponseWriter, r *http.Request, users []system.LinuxUser, releases []domain.DeploymentRelease) {
	spec := system.RollbackSpec{
		TargetDirectory:   r.FormValue("rollback_target_directory"),
		RunAsUser:         r.FormValue("rollback_run_as_user"),
		ReleaseCommitSHA:  r.FormValue("release_commit_sha"),
		PostDeployCommand: r.FormValue("rollback_post_deploy_command"),
	}

	result, err := a.deploys.Rollback(spec)
	if err != nil {
		a.recordAudit(r.Context(), "deploy.rollback", spec.TargetDirectory, "failure", map[string]any{"run_as_user": spec.RunAsUser, "commit_sha": spec.ReleaseCommitSHA, "error": err.Error()})
		a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
			Title:          "Deploys",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   err.Error(),
			CommandOutput:  result.Output,
			DeploymentReleases: releases,
		})
		return
	}

	if a.store != nil {
		_ = a.store.CreateDeploymentRelease(r.Context(), domain.DeploymentRelease{
			RepositoryURL:     "",
			BranchName:        "rollback",
			TargetDirectory:   spec.TargetDirectory,
			RunAsUser:         spec.RunAsUser,
			Action:            result.Action,
			Status:            "success",
			CommitSHA:         result.CommitSHA,
			PreviousCommitSHA: result.PreviousCommitSHA,
			Output:            result.Output,
		})
		if entries, listErr := a.store.ListDeploymentReleases(r.Context(), 12); listErr == nil {
			releases = entries
		}
	}

	a.recordAudit(r.Context(), "deploy.rollback", spec.TargetDirectory, "success", map[string]any{"run_as_user": spec.RunAsUser, "commit_sha": spec.ReleaseCommitSHA})
	a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
		Title:          "Deploys",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     users,
		SuccessMessage: "Rollback completed successfully.",
		ResultPath:     spec.TargetDirectory,
		CommandOutput:  result.Output,
		CommitSHA:      result.CommitSHA,
		PreviousCommitSHA: result.PreviousCommitSHA,
		DeploymentReleases: releases,
	})
}

func (a *App) renderSiteDetails(w http.ResponseWriter, r *http.Request, site domain.ManagedSite, repositoryStatus system.RepositoryStatus, runtimeStatus system.RuntimeStatus, gitAuthStatus system.GitAuthStatus, releases []domain.DeploymentRelease, data TemplateData) {
	data.Title = site.Name + " details"
	data.DatabaseStatus = a.databaseStatus(r.Context())
	data.Metrics = a.metrics.Snapshot()
	data.SelectedSite = site
	if data.SiteDetailTab == "" {
		data.SiteDetailTab = "overview"
	}
	data.RepositoryStatus = repositoryStatus
	data.RuntimeStatus = runtimeStatus
	data.GitAuthStatus = gitAuthStatus
	data.DeploymentReleases = releases
	data.AutoDeployEnabled = data.AutoDeployEnabled || site.AutoDeployEnabled
	data.AutoDeployBranch = firstNonEmpty(data.AutoDeployBranch, site.AutoDeployBranch, repositoryStatus.Branch, "main")
	data.AutoDeploySecret = firstNonEmpty(data.AutoDeploySecret, site.AutoDeploySecret)
	data.AutoDeployCommand = firstNonEmpty(data.AutoDeployCommand, site.AutoDeployCommand)
	data.AutoDeployNotifyEmail = firstNonEmpty(data.AutoDeployNotifyEmail, site.AutoDeployNotifyEmail)
	data.AutoDeployWebhookURL = buildAutoDeployWebhookURL(a.cfg.BaseURL, site.Name, data.AutoDeploySecret)
	data.AutoDeployWebhookAuthHint = autoDeployWebhookAuthHint()
	if len(releases) > 0 {
		data.LatestDeploymentRelease = releases[0]
	}
	data.PackageScripts = readPackageJSONScripts(site.RootDirectory)
	data.NpmScriptNodeVersion = runtimeStatus.DefaultNodeVersion
	if data.RuntimeCommandNodeVersion == "" {
		data.RuntimeCommandNodeVersion = runtimeStatus.DefaultNodeVersion
	}
	data.DatabaseAccess, _ = a.databases.ListDatabaseAccess()
	data.LinuxUsers = a.listLinuxUsers()
	if commands, err := a.store.ListSiteRuntimeCommands(r.Context(), site.ID); err == nil {
		data.SiteRuntimeCommands = commands
	}
	if subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID); err == nil {
		data.SiteSubdomains = subdomains
	}
	if entry, err := a.store.GetLatestAuditLogByActionAndTarget(r.Context(), "deploy.webhook", site.Name); err == nil {
		entry.Metadata = summarizeAuditMetadata(entry.Metadata)
		data.LatestWebhookAudit = entry
	}
	if data.SubdomainMode == "" {
		data.SubdomainMode = "reverse_proxy"
	}
	envPath := filepath.Join(site.RootDirectory, ".env")
	var envContent string
	if _, err := a.helper.Call(r.Context(), "files.read_env", map[string]string{"path": envPath}, &envContent); err == nil {
		data.EnvFileContent = envContent
	}
	if data.GitRepositoryURL == "" {
		data.GitRepositoryURL = repositoryStatus.RemoteURL
	}
	if data.GitBranch == "" {
		if repositoryStatus.Branch != "" {
			data.GitBranch = repositoryStatus.Branch
		} else {
			data.GitBranch = "main"
		}
	}
	if data.RuntimeNodeVersion == "" {
		data.RuntimeNodeVersion = runtimeStatus.DefaultNodeVersion
	}
	if data.PM2NodeVersion == "" {
		data.PM2NodeVersion = firstNonEmpty(runtimeStatus.DefaultNodeVersion, data.RuntimeNodeVersion)
	}
	if data.PM2ProcessName == "" {
		data.PM2ProcessName = site.Name
	}
	if data.PM2ScriptPath == "" {
		data.PM2ScriptPath = "ecosystem.config.cjs"
	}
	// Read ecosystem.config.cjs to detect port
	ecosystemPath := filepath.Join(site.RootDirectory, "ecosystem.config.cjs")
	var ecosystemContent string
	if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]string{"path": ecosystemPath}, &ecosystemContent); err == nil && ecosystemContent != "" {
		if port := extractEcosystemPort(ecosystemContent); port != "" {
			data.EcosystemPort = port
		}
	}
	if data.GitCredentialProtocol == "" {
		data.GitCredentialProtocol = firstNonEmpty(gitAuthStatus.RepositoryProtocol, "https")
	}
	if data.GitCredentialHost == "" {
		data.GitCredentialHost = gitAuthStatus.RepositoryHost
	}
	a.render(r.Context(), w, r.URL.Path, "site_details.html", data)
}

func extractEcosystemPort(content string) string {
	// Match port: 3000 or PORT: 3000 or "port": 3000 or args: "--port 3000" etc.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bport["'\s]*[:=]["'\s]*(\d{2,5})`),
		regexp.MustCompile(`(?i)--port\s+(\d{2,5})`),
	}
	for _, pat := range patterns {
		if m := pat.FindStringSubmatch(content); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func readPackageJSONScripts(rootDir string) []string {
	data, err := os.ReadFile(filepath.Join(rootDir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	names := make([]string, 0, len(pkg.Scripts))
	for name := range pkg.Scripts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func deployErrorMessage(err error) string {
	message := err.Error()
	switch {
	case errors.Is(err, system.ErrInvalidRepoURL):
		message = "Repository URL is invalid. Use an https or git@ style URL."
	case errors.Is(err, system.ErrInvalidBranch):
		message = "Branch name is invalid."
	case errors.Is(err, system.ErrInvalidTargetDirectory):
		message = "Target directory must be an absolute path."
	case errors.Is(err, system.ErrInvalidRunAsUser):
		message = "Run-as user is invalid for Ubuntu deployment."
	}
	return message
}

func runtimeErrorMessage(err error) string {
	message := err.Error()
	switch {
	case errors.Is(err, system.ErrInvalidNodeVersion):
		message = "Node version is invalid. Use values like 20, 20.11.1, or lts/*."
	case errors.Is(err, system.ErrNVMNotInstalled):
		message = "NVM is not installed yet for this Linux user. Install NVM first."
	case errors.Is(err, system.ErrInvalidProcessName):
		message = "PM2 process name is invalid."
	case errors.Is(err, system.ErrInvalidScriptPath):
		message = "Script path is invalid. Use a relative file like server.js or an absolute path."
	case errors.Is(err, system.ErrInvalidArguments):
		message = "PM2 process arguments contain unsupported characters."
	case errors.Is(err, system.ErrInvalidTargetDirectory):
		message = "Target directory must be an absolute path."
	case errors.Is(err, system.ErrInvalidUsername), errors.Is(err, system.ErrInvalidRunAsUser):
		message = "Linux user is invalid for this runtime action."
	}
	return message
}

func gitAuthErrorMessage(err error) string {
	message := err.Error()
	switch {
	case errors.Is(err, system.ErrInvalidGitHost):
		message = "Git host is invalid."
	case errors.Is(err, system.ErrInvalidCredentialProtocol):
		message = "Credential protocol must be http or https."
	case errors.Is(err, system.ErrInvalidCredentialUsername):
		message = "Credential username is invalid."
	case errors.Is(err, system.ErrInvalidCredentialPassword):
		message = "Credential password or token is required."
	case errors.Is(err, system.ErrInvalidUsername):
		message = "Linux user is invalid for this git authentication action."
	}
	return message
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (a *App) handleProcesses(w http.ResponseWriter, r *http.Request) {
	users := a.listLinuxUsers()

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "processes.html", TemplateData{
			Title:          "Processes",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "processes.html", TemplateData{
			Title:          "Processes",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   "The submitted process form could not be parsed.",
		})
		return
	}

	user := r.FormValue("run_as_user")
	action := r.FormValue("action")
	processName := r.FormValue("process_name")
	logLines, _ := strconv.Atoi(r.FormValue("log_lines"))

	var (
		output  string
		err     error
		message string
	)

	switch action {
	case "list":
		output, err = a.pm2.List(user)
		message = "PM2 process list loaded successfully."
	case "start":
		output, err = a.pm2.Start(user, processName)
		message = "PM2 process started successfully."
	case "stop":
		output, err = a.pm2.Stop(user, processName)
		message = "PM2 process stopped successfully."
	case "restart":
		output, err = a.pm2.Restart(user, processName)
		message = "PM2 process restarted successfully."
	case "reload":
		output, err = a.pm2.Reload(user, processName)
		message = "PM2 process reloaded successfully."
	case "logs":
		output, err = a.pm2.Logs(user, processName, logLines)
		message = "PM2 logs loaded successfully."
	default:
		err = errors.New("invalid process action")
	}

	if err != nil {
		a.recordAudit(r.Context(), "pm2."+action, processName, "failure", map[string]any{"run_as_user": user, "error": err.Error()})
		a.render(r.Context(), w, r.URL.Path, "processes.html", TemplateData{
			Title:          "Processes",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			RequestError:   err.Error(),
			CommandOutput:  output,
		})
		return
	}

	a.recordAudit(r.Context(), "pm2."+action, processName, "success", map[string]any{"run_as_user": user})
	a.render(r.Context(), w, r.URL.Path, "processes.html", TemplateData{
		Title:          "Processes",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     users,
		SuccessMessage: message,
		CommandOutput:  output,
	})
}

func (a *App) handlePHP(w http.ResponseWriter, r *http.Request) {
	sites := a.listManagedSites(r)
	versions := a.listPHPVersions()

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "php.html", TemplateData{
			Title:          "PHP",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			ManagedSites:   sites,
			PHPVersions:    versions,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.store == nil {
		a.render(r.Context(), w, r.URL.Path, "php.html", TemplateData{
			Title:          "PHP",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   "Managed site storage is not configured yet. Set PANEL_DATABASE_DSN first.",
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "php.html", TemplateData{
			Title:          "PHP",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   "The submitted PHP form could not be parsed.",
		})
		return
	}

	siteName := r.FormValue("site_name")
	phpVersion := r.FormValue("php_version")
	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		a.recordAudit(r.Context(), "php.switch", siteName, "failure", map[string]any{"version": phpVersion, "error": err.Error()})
		a.render(r.Context(), w, r.URL.Path, "php.html", TemplateData{
			Title:          "PHP",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			RequestError:   "Managed site could not be found by that name.",
		})
		return
	}

	if err := a.php.SwitchSiteVersion(site.NginxConfigPath, phpVersion); err != nil {
		a.recordAudit(r.Context(), "php.switch", siteName, "failure", map[string]any{"version": phpVersion, "config_path": site.NginxConfigPath, "error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidPHPVersion) {
			message = "PHP version must look like 8.2 or 8.3."
		}
		a.render(r.Context(), w, r.URL.Path, "php.html", TemplateData{
			Title:          "PHP",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			ManagedSites:   sites,
			PHPVersions:    versions,
			RequestError:   message,
		})
		return
	}

	_ = a.store.UpdateManagedSitePHPVersion(r.Context(), siteName, phpVersion)
	a.recordAudit(r.Context(), "php.switch", siteName, "success", map[string]any{"version": phpVersion, "config_path": site.NginxConfigPath})
	sites = a.listManagedSites(r)
	a.render(r.Context(), w, r.URL.Path, "php.html", TemplateData{
		Title:          "PHP",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		ManagedSites:   sites,
		PHPVersions:    versions,
		SuccessMessage: "PHP-FPM version switched successfully.",
		ResultPath:     site.NginxConfigPath,
	})
}

func (a *App) listLinuxUsers() []system.LinuxUser {
	if a.users == nil {
		return nil
	}
	users, err := a.users.ListLinuxUsers()
	if err != nil {
		return nil
	}
	return users
}

func (a *App) listManagedSites(r *http.Request) []domain.ManagedSite {
	if a.store == nil {
		return nil
	}
	sites, err := a.store.ListManagedSites(r.Context())
	if err != nil {
		return nil
	}
	return sites
}

func (a *App) listSiteDeploymentReleases(r *http.Request, targetDirectory string, runAsUser string) []domain.DeploymentRelease {
	if a.store == nil {
		return nil
	}
	releases, err := a.store.ListDeploymentReleases(r.Context(), 50)
	if err != nil {
		return nil
	}
	filtered := make([]domain.DeploymentRelease, 0, len(releases))
	for _, release := range releases {
		if release.TargetDirectory != targetDirectory {
			continue
		}
		if runAsUser != "" && release.RunAsUser != runAsUser {
			continue
		}
		filtered = append(filtered, release)
	}
	return filtered
}

func (a *App) listPHPVersions() []string {
	if a.php == nil {
		return nil
	}
	versions, err := a.php.ListAvailableVersions()
	if err != nil {
		return nil
	}
	return versions
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs := []domain.AuditLog{}
	if a.store != nil {
		if entries, err := a.store.ListAuditLogs(r.Context(), 50); err == nil {
			logs = entries
		}
	}
	a.render(r.Context(), w, r.URL.Path, "logs.html", TemplateData{
		Title:          "Logs",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		AuditLogs:      logs,
	})
}

func randomPassword(length int) (string, error) {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(buffer)
	if len(encoded) > length {
		return encoded[:length], nil
	}
	return encoded, nil
}
