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
	template "html/template"
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
	"time"

	"github.com/kaganyegin/server-side-control/internal/auth"
	"github.com/kaganyegin/server-side-control/internal/domain"
	"github.com/kaganyegin/server-side-control/internal/store"
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
		data := TemplateData{Title: "Login", LoginStage: "username"}
		if pendingLogin, err := a.currentPendingLogin(r); err == nil {
			data.LoginRequiresTOTP = true
			data.LoginUsername = pendingLogin.Identity.Username
		} else {
			a.clearPendingLoginCookie(w)
		}
		a.render(r.Context(), w, r.URL.Path, "login.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit all POST login attempts by client IP
	clientIP := a.clientAddress(r)
	if err := a.loginRateLimiter.Check(clientIP, ""); err != nil {
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title:        "Login",
			LoginStage:   "username",
			RequestError: "Too many login attempts. Please wait before trying again.",
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title:        "Login",
			LoginStage:   "username",
			RequestError: "The submitted form could not be parsed.",
		})
		return
	}

	if r.FormValue("login_action") == "verify_totp" {
		pendingLogin, err := a.currentPendingLogin(r)
		if err != nil {
			a.clearPendingLoginCookie(w)
			a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
				Title:        "Login",
				RequestError: "Two-step verification step expired. Sign in again.",
			})
			return
		}

		data := TemplateData{
			Title:             "Login",
			LoginRequiresTOTP: true,
			LoginUsername:     pendingLogin.Identity.Username,
			LoginStage:        "totp",
			TOTPCode:          strings.TrimSpace(r.FormValue("totp_code")),
			RecoveryCode:      strings.TrimSpace(r.FormValue("recovery_code")),
		}
		security, securityErr := a.store.GetPanelUserSecurity(r.Context(), pendingLogin.Identity.Username)
		if securityErr != nil {
			data.RequestError = "Two-step verification status could not be checked: " + securityErr.Error()
			a.render(r.Context(), w, r.URL.Path, "login.html", data)
			return
		}
		if !security.TOTPEnabled || strings.TrimSpace(security.TOTPSecret) == "" {
			a.pendingLogins.Delete(r.Context(), pendingLogin.ID)
			a.clearPendingLoginCookie(w)
			data.LoginRequiresTOTP = false
			data.LoginStage = "username"
			data.LoginUsername = ""
			data.TOTPCode = ""
			data.RequestError = "Two-step verification is no longer enabled for this account. Sign in again."
			a.render(r.Context(), w, r.URL.Path, "login.html", data)
			return
		}
		verifiedWithRecoveryCode := false
		if data.RecoveryCode != "" {
			recoveryHash := auth.HashRecoveryCode(data.RecoveryCode)
			remainingHashes := make([]string, 0, len(security.RecoveryCodes))
			matched := false
			for _, storedHash := range security.RecoveryCodes {
				if !matched && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(storedHash)), []byte(recoveryHash)) == 1 {
					matched = true
					continue
				}
				remainingHashes = append(remainingHashes, storedHash)
			}
			if !matched {
				a.recordAudit(r.Context(), "auth.login.recovery", pendingLogin.Identity.Username, "failure", map[string]any{"provider": pendingLogin.Identity.AuthProvider})
				a.loginRateLimiter.RecordFailure(clientIP, pendingLogin.Identity.Username)
				data.RequestError = "Recovery code is invalid."
				a.render(r.Context(), w, r.URL.Path, "login.html", data)
				return
			}
			if err := a.store.SavePanelUserRecoveryCodes(r.Context(), pendingLogin.Identity.Username, remainingHashes); err != nil {
				data.RequestError = "Recovery code state could not be updated: " + err.Error()
				a.render(r.Context(), w, r.URL.Path, "login.html", data)
				return
			}
			verifiedWithRecoveryCode = true
		} else if !auth.ValidateTOTP(security.TOTPSecret, data.TOTPCode, time.Now()) {
			a.recordAudit(r.Context(), "auth.login.2fa", pendingLogin.Identity.Username, "failure", map[string]any{"provider": pendingLogin.Identity.AuthProvider})
			a.loginRateLimiter.RecordFailure(clientIP, pendingLogin.Identity.Username)
			data.RequestError = "Verification code is invalid."
			a.render(r.Context(), w, r.URL.Path, "login.html", data)
			return
		}

		session, err := a.sessions.Create(r.Context(), pendingLogin.Identity, a.clientAddress(r))
		if err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		a.loginRateLimiter.RecordSuccess(clientIP, pendingLogin.Identity.Username)
		_ = a.store.TouchPanelUserLastLogin(r.Context(), pendingLogin.Identity.Username)
		a.pendingLogins.Delete(r.Context(), pendingLogin.ID)
		a.clearPendingLoginCookie(w)
		ctx := auth.ContextWithIdentity(r.Context(), pendingLogin.Identity)
		provider := pendingLogin.Identity.AuthProvider + "+totp"
		if verifiedWithRecoveryCode {
			provider = pendingLogin.Identity.AuthProvider + "+recovery"
		}
		a.recordAudit(ctx, "auth.login", pendingLogin.Identity.Username, "success", map[string]any{"provider": provider})
		a.setSessionCookie(w, r, session)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	loginAction := strings.TrimSpace(r.FormValue("login_action"))
	if username == "" {
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title:        "Login",
			LoginStage:   "username",
			RequestError: "Username is required.",
		})
		return
	}
	if loginAction == "choose_username" || (loginAction == "" && strings.TrimSpace(r.FormValue("password")) == "") {
		passkeys, err := a.store.ListPanelUserPasskeys(r.Context(), username)
		if err != nil {
			a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
				Title:                "Login",
				LoginStage:           "passkey",
				LoginUsername:        username,
				LoginPasswordVisible: true,
				RequestError:         "Sign-in method could not be prepared. Continue with your password.",
			})
			return
		}
		data := TemplateData{
			Title:                 "Login",
			LoginStage:            "passkey",
			LoginUsername:         username,
			LoginPasswordVisible:  true,
			LoginPasskeyAvailable: len(passkeys) > 0,
			LoginPasskeyAutostart: false,
		}
		if len(passkeys) > 0 {
			data.SuccessMessage = "Choose how you want to continue. Passkey sign-in opens directly, or you can continue with your password."
		}
		a.render(r.Context(), w, r.URL.Path, "login.html", data)
		return
	}
	password := r.FormValue("password")
	identity, err := a.auth.Authenticate(r.Context(), username, password)
	if err != nil {
		a.recordAudit(r.Context(), "auth.login", username, "failure", map[string]any{"provider": "login-form"})
		a.loginRateLimiter.RecordFailure(clientIP, username)
		message := "Invalid username or password."
		if errors.Is(err, auth.ErrUnsupported) {
			message = "PAM authentication is not available on this host. Use the bootstrap account until the Ubuntu target environment is ready."
		}
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title:                "Login",
			LoginStage:           "password",
			LoginUsername:        username,
			LoginPasswordVisible: true,
			RequestError:         message,
		})
		return
	}

	if a.beginSecondFactorLogin(w, r, *identity, "Password accepted. Enter the 6-digit verification code from Apple Passwords or another authenticator app.") {
		return
	}

	session, err := a.sessions.Create(r.Context(), *identity, a.clientAddress(r))
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	a.loginRateLimiter.RecordSuccess(clientIP, identity.Username)
	_ = a.store.TouchPanelUserLastLogin(r.Context(), identity.Username)
	a.clearPendingLoginCookie(w)
	ctx := auth.ContextWithIdentity(r.Context(), *identity)
	a.recordAudit(ctx, "auth.login", identity.Username, "success", map[string]any{"provider": identity.AuthProvider})
	a.setSessionCookie(w, r, session)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if pendingLogin, err := a.currentPendingLogin(r); err == nil {
		a.pendingLogins.Delete(r.Context(), pendingLogin.ID)
	}
	a.clearPendingLoginCookie(w)
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

	// Pre-compute usage percentages for template (no arithmetic in template)
	memPct := 0
	if snapshot.MemoryTotalMB > 0 {
		memPct = int(snapshot.MemoryUsedMB * 100 / snapshot.MemoryTotalMB)
	}
	diskPct := 0
	if snapshot.DiskTotalGB > 0 {
		diskPct = int(snapshot.DiskUsedGB * 100 / snapshot.DiskTotalGB)
	}

	// Recent deploy releases
	recentDeploys := a.dashboardRecentDeploys(r.Context())

	// PM2 processes from all managed site linux users
	pm2Entries := a.dashboardPM2Entries(r)
	sites := a.listManagedSites(r)

	a.render(r.Context(), w, r.URL.Path, "dashboard.html", TemplateData{
		Title:               "Dashboard",
		DatabaseStatus:      a.databaseStatus(r.Context()),
		Metrics:             snapshot,
		Alerts:              alerts,
		ManagedSites:        sites,
		DeploymentReleases:  recentDeploys,
		DashboardPM2Entries: pm2Entries,
		DashboardMemPct:     memPct,
		DashboardDiskPct:    diskPct,
	})
}

func (a *App) handleDashboardSection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	section := strings.TrimSpace(r.URL.Query().Get("name"))
	data := TemplateData{}
	switch section {
	case "recent-deploys":
		data.DeploymentReleases = a.dashboardRecentDeploys(r.Context())
		a.renderNamedTemplate(r.Context(), w, "dashboard.html", "dashboard-recent-deploys", data)
	case "top-processes":
		data.Metrics = a.metrics.Snapshot()
		a.renderNamedTemplate(r.Context(), w, "dashboard.html", "dashboard-top-processes", data)
	case "pm2-processes":
		data.DashboardPM2Entries = a.dashboardPM2Entries(r)
		a.renderNamedTemplate(r.Context(), w, "dashboard.html", "dashboard-pm2-processes", data)
	default:
		http.Error(w, "unknown dashboard section", http.StatusBadRequest)
	}
}

func (a *App) dashboardRecentDeploys(ctx context.Context) []domain.DeploymentRelease {
	if a.store == nil {
		return nil
	}
	if releases, err := a.store.ListDeploymentReleases(ctx, 10); err == nil {
		return releases
	}
	return nil
}

func (a *App) dashboardPM2Entries(r *http.Request) []DashboardPM2Entry {
	sites := a.listManagedSites(r)
	seen := make(map[string]bool)
	entries := make([]DashboardPM2Entry, 0)
	for _, site := range sites {
		user := strings.TrimSpace(site.OwnerLinuxUser)
		if user == "" || seen[user] {
			continue
		}
		seen[user] = true
		if listText, err := a.pm2.List(user); err == nil && strings.TrimSpace(listText) != "" {
			entries = append(entries, DashboardPM2Entry{User: user, ListText: strings.TrimSpace(listText)})
		}
	}
	return entries
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())
	data := TemplateData{
		Title:                "Settings",
		DatabaseStatus:       a.databaseStatus(r.Context()),
		Metrics:              a.metrics.Snapshot(),
		PanelListenAddr:      a.cfg.ListenAddr,
		PanelBaseURL:         a.cfg.BaseURL,
		PanelServiceName:     firstNonEmpty(a.cfg.ServiceName, "server-side-control"),
		SubdomainRootBaseDir: strings.TrimSpace(a.cfg.SubdomainRootBaseDir),
		SMTPHost:             a.cfg.SMTPHost,
		SMTPPort:             firstNonEmpty(a.cfg.SMTPPort, "587"),
		SMTPUsername:         a.cfg.SMTPUsername,
		SMTPPassword:         a.cfg.SMTPPassword,
		SMTPFrom:             a.cfg.SMTPFrom,
		SMTPTo:               a.cfg.SMTPTo,
		OpenAIAPIKey:         a.cfg.OpenAIAPIKey,
		OpenAIModel:          firstNonEmpty(strings.TrimSpace(a.cfg.OpenAIModel), "gpt-4.1-mini"),
		OpenAIConfigured:     a.openAIConfigured(),
		PanelEnvPath:         a.cfg.EnvPath,
		AWSAccessKeyID:       a.cfg.AWSAccessKeyID,
		AWSSecretAccessKey:   a.cfg.AWSSecretAccessKey,
		AWSConfigured:        a.dns.Configured(),
	}
	data.PanelDomain = panelDomainFromBaseURL(a.cfg.BaseURL)
	data.PanelProxyConfigPath = filepath.Join(a.cfg.NginxAvailableDir, "server-side-control-panel.conf")
	if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]string{"path": data.PanelProxyConfigPath}, &data.PanelProxyConfig); err != nil {
		data.PanelProxyConfig = ""
	}
	if data.PanelDomain != "" {
		_, _ = a.helper.Call(r.Context(), "panel.inspect_tls", map[string]string{"domain": data.PanelDomain}, &data.PanelTLSStatus)
	}
	security, securityErr := a.store.GetPanelUserSecurity(r.Context(), identity.Username)
	if securityErr == nil {
		data.TOTPEnabled = security.TOTPEnabled
		data.TOTPSetupSecret = strings.TrimSpace(security.TOTPSecret)
		data.TOTPSetupPending = data.TOTPSetupSecret != "" && !security.TOTPEnabled
		data.RecoveryCodesRemaining = len(security.RecoveryCodes)
		if data.TOTPSetupSecret != "" {
			data.TOTPProvisioningURI = auth.BuildTOTPProvisioningURI(a.cfg.AppName, identity.Username, data.TOTPSetupSecret)
		}
	} else {
		data.RequestError = "Login security status could not be loaded: " + securityErr.Error()
	}
	if passkeys, err := a.store.ListPanelUserPasskeys(r.Context(), identity.Username); err == nil {
		data.Passkeys = passkeys
	} else if data.RequestError == "" {
		data.RequestError = "Passkey list could not be loaded: " + err.Error()
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
	data.SubdomainRootBaseDir = firstNonEmpty(strings.TrimSpace(r.FormValue("subdomain_root_base_dir")), data.SubdomainRootBaseDir)
	data.SMTPHost = strings.TrimSpace(r.FormValue("smtp_host"))
	data.SMTPPort = firstNonEmpty(strings.TrimSpace(r.FormValue("smtp_port")), "587")
	data.SMTPUsername = strings.TrimSpace(r.FormValue("smtp_username"))
	data.SMTPPassword = r.FormValue("smtp_password")
	data.SMTPFrom = strings.TrimSpace(r.FormValue("smtp_from"))
	data.SMTPTo = strings.TrimSpace(r.FormValue("smtp_to"))
	data.OpenAIAPIKey = firstNonEmpty(r.FormValue("openai_api_key"), data.OpenAIAPIKey)
	data.OpenAIModel = firstNonEmpty(strings.TrimSpace(r.FormValue("openai_model")), data.OpenAIModel, "gpt-4.1-mini")
	data.OpenAIConfigured = strings.TrimSpace(data.OpenAIAPIKey) != ""
	data.AWSAccessKeyID = firstNonEmpty(strings.TrimSpace(r.FormValue("aws_access_key_id")), data.AWSAccessKeyID)
	data.AWSSecretAccessKey = firstNonEmpty(r.FormValue("aws_secret_access_key"), data.AWSSecretAccessKey)
	data.AWSConfigured = strings.TrimSpace(data.AWSAccessKeyID) != "" && strings.TrimSpace(data.AWSSecretAccessKey) != ""
	data.TOTPCode = strings.TrimSpace(r.FormValue("totp_code"))
	data.TOTPSetupSecret = firstNonEmpty(strings.TrimSpace(r.FormValue("totp_secret")), data.TOTPSetupSecret)
	data.PasskeyLabel = strings.TrimSpace(r.FormValue("passkey_label"))
	if data.PanelDomain == "" {
		data.PanelDomain = panelDomainFromBaseURL(data.PanelBaseURL)
	}

	switch r.FormValue("settings_action") {
	case "start_totp_setup":
		secret, err := auth.GenerateTOTPSecret()
		if err != nil {
			data.RequestError = "Two-step verification secret could not be generated: " + err.Error()
			break
		}
		if err := a.store.SavePanelUserTOTP(r.Context(), identity.Username, secret, false); err != nil {
			data.RequestError = "Two-step verification setup could not be saved: " + err.Error()
			break
		}
		data.TOTPEnabled = false
		data.TOTPSetupPending = true
		data.TOTPSetupSecret = secret
		data.TOTPProvisioningURI = auth.BuildTOTPProvisioningURI(a.cfg.AppName, identity.Username, secret)
		data.SuccessMessage = "Two-step verification setup created. Add it to Apple Passwords or another TOTP app, then confirm with a code below."
		a.recordAudit(r.Context(), "panel.totp.setup", identity.Username, "success", nil)
	case "enable_totp":
		currentSecurity, err := a.store.GetPanelUserSecurity(r.Context(), identity.Username)
		if err != nil {
			data.RequestError = "Two-step verification status could not be reloaded: " + err.Error()
			break
		}
		secret := firstNonEmpty(strings.TrimSpace(currentSecurity.TOTPSecret), strings.TrimSpace(data.TOTPSetupSecret))
		if secret == "" {
			data.RequestError = "Start two-step verification setup first."
			break
		}
		if !auth.ValidateTOTP(secret, data.TOTPCode, time.Now()) {
			data.RequestError = "Verification code is invalid."
			break
		}
		if err := a.store.SavePanelUserTOTP(r.Context(), identity.Username, secret, true); err != nil {
			data.RequestError = "Two-step verification could not be enabled: " + err.Error()
			break
		}
		data.TOTPEnabled = true
		data.TOTPSetupPending = false
		data.TOTPSetupSecret = secret
		data.TOTPProvisioningURI = auth.BuildTOTPProvisioningURI(a.cfg.AppName, identity.Username, data.TOTPSetupSecret)
		data.TOTPCode = ""
		data.SuccessMessage = "Two-step verification enabled successfully."
		a.recordAudit(r.Context(), "panel.totp.enable", identity.Username, "success", nil)
	case "generate_recovery_codes":
		if !security.TOTPEnabled || strings.TrimSpace(security.TOTPSecret) == "" {
			data.RequestError = "Enable two-step verification before generating recovery codes."
			break
		}
		plainCodes, hashes, err := auth.GenerateRecoveryCodes(8)
		if err != nil {
			data.RequestError = "Recovery codes could not be generated: " + err.Error()
			break
		}
		if err := a.store.SavePanelUserRecoveryCodes(r.Context(), identity.Username, hashes); err != nil {
			data.RequestError = "Recovery codes could not be saved: " + err.Error()
			break
		}
		data.RecoveryCodes = plainCodes
		data.RecoveryCodesRemaining = len(hashes)
		data.SuccessMessage = "Recovery codes generated. Store them now; they are shown only once."
		a.recordAudit(r.Context(), "panel.totp.recovery.generate", identity.Username, "success", map[string]any{"count": len(hashes)})
	case "disable_totp":
		if !security.TOTPEnabled || strings.TrimSpace(security.TOTPSecret) == "" {
			data.RequestError = "Two-step verification is not enabled for this account."
			break
		}
		if !auth.ValidateTOTP(security.TOTPSecret, data.TOTPCode, time.Now()) {
			data.RequestError = "Verification code is invalid."
			break
		}
		if err := a.store.DisablePanelUserTOTP(r.Context(), identity.Username); err != nil {
			data.RequestError = "Two-step verification could not be disabled: " + err.Error()
			break
		}
		data.TOTPEnabled = false
		data.TOTPSetupPending = false
		data.TOTPSetupSecret = ""
		data.TOTPProvisioningURI = ""
		data.TOTPCode = ""
		data.RecoveryCodes = nil
		data.RecoveryCodesRemaining = 0
		data.SuccessMessage = "Two-step verification disabled successfully."
		a.recordAudit(r.Context(), "panel.totp.disable", identity.Username, "success", nil)
	case "delete_passkey":
		passkeyID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("passkey_id")), 10, 64)
		if err != nil || passkeyID <= 0 {
			data.RequestError = "Passkey id is invalid."
			break
		}
		if err := a.store.DeletePanelUserPasskey(r.Context(), identity.Username, passkeyID); err != nil {
			data.RequestError = "Passkey could not be deleted: " + err.Error()
			break
		}
		data.SuccessMessage = "Passkey removed successfully."
		a.recordAudit(r.Context(), "panel.passkey.delete", identity.Username, "success", map[string]any{"passkey_id": passkeyID})
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
		updatedCfg.SubdomainRootBaseDir = data.SubdomainRootBaseDir
		updatedCfg.SMTPHost = data.SMTPHost
		updatedCfg.SMTPPort = data.SMTPPort
		updatedCfg.SMTPUsername = data.SMTPUsername
		updatedCfg.SMTPPassword = data.SMTPPassword
		updatedCfg.SMTPFrom = data.SMTPFrom
		updatedCfg.SMTPTo = data.SMTPTo
		updatedCfg.OpenAIAPIKey = data.OpenAIAPIKey
		updatedCfg.OpenAIModel = data.OpenAIModel
		updatedCfg.AWSAccessKeyID = data.AWSAccessKeyID
		updatedCfg.AWSSecretAccessKey = data.AWSSecretAccessKey
		resultPath, err := a.helper.Call(r.Context(), "panel.write_env", map[string]string{"content": updatedCfg.ToEnv()}, nil)
		if err != nil {
			data.RequestError = "Panel config could not be saved: " + err.Error()
			break
		}
		a.cfg = updatedCfg
		a.dns = system.NewRoute53DNSManager(updatedCfg.AWSAccessKeyID, updatedCfg.AWSSecretAccessKey)
		data.AWSConfigured = a.dns.Configured()
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
	if refreshedSecurity, err := a.store.GetPanelUserSecurity(r.Context(), identity.Username); err == nil {
		data.TOTPEnabled = refreshedSecurity.TOTPEnabled
		data.TOTPSetupSecret = strings.TrimSpace(refreshedSecurity.TOTPSecret)
		data.TOTPSetupPending = data.TOTPSetupSecret != "" && !refreshedSecurity.TOTPEnabled
		data.RecoveryCodesRemaining = len(refreshedSecurity.RecoveryCodes)
		if data.TOTPSetupSecret != "" {
			data.TOTPProvisioningURI = auth.BuildTOTPProvisioningURI(a.cfg.AppName, identity.Username, data.TOTPSetupSecret)
		}
	}
	if passkeys, err := a.store.ListPanelUserPasskeys(r.Context(), identity.Username); err == nil {
		data.Passkeys = passkeys
	}
	a.render(r.Context(), w, r.URL.Path, "settings.html", data)
}

func (a *App) completeAuthenticatedLogin(w http.ResponseWriter, r *http.Request, identity auth.Identity, provider string) bool {
	session, err := a.sessions.Create(r.Context(), identity, a.clientAddress(r))
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return false
	}
	_ = a.store.TouchPanelUserLastLogin(r.Context(), identity.Username)
	a.clearPendingLoginCookie(w)
	ctx := auth.ContextWithIdentity(r.Context(), identity)
	a.recordAudit(ctx, "auth.login", identity.Username, "success", map[string]any{"provider": provider})
	a.setSessionCookie(w, r, session)
	return true
}

func (a *App) beginSecondFactorLogin(w http.ResponseWriter, r *http.Request, identity auth.Identity, successMessage string) bool {
	security, securityErr := a.store.GetPanelUserSecurity(r.Context(), identity.Username)
	if securityErr != nil {
		message := "Two-step verification status could not be loaded: " + securityErr.Error()
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": message})
			return true
		}
		a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
			Title:        "Login",
			RequestError: message,
		})
		return true
	}
	if !security.TOTPEnabled || strings.TrimSpace(security.TOTPSecret) == "" {
		return false
	}
	pendingLogin, err := a.pendingLogins.Create(r.Context(), identity, a.clientAddress(r))
	if err != nil {
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login challenge error"})
			return true
		}
		http.Error(w, "login challenge error", http.StatusInternalServerError)
		return true
	}
	a.setPendingLoginCookie(w, r, pendingLogin)
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]string{"redirect": "/login"})
		return true
	}
	a.render(r.Context(), w, r.URL.Path, "login.html", TemplateData{
		Title:             "Login",
		SuccessMessage:    successMessage,
		LoginStage:        "totp",
		LoginRequiresTOTP: true,
		LoginUsername:     identity.Username,
	})
	return true
}

func (a *App) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form data"})
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}
	passkeys, err := a.store.ListPanelUserPasskeys(r.Context(), username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "passkeys could not be loaded"})
		return
	}
	if len(passkeys) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Passkey sign-in is not available. Use your password instead."})
		return
	}
	challenge, err := a.webauthnChallenges.Create(r.Context(), username, "login", a.clientAddress(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "passkey challenge could not be created"})
		return
	}
	allowCredentials := make([]map[string]string, 0, len(passkeys))
	for _, passkey := range passkeys {
		allowCredentials = append(allowCredentials, map[string]string{"type": "public-key", "id": passkey.CredentialID})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challenge.ID,
		"publicKey": map[string]any{
			"challenge":        challenge.Challenge,
			"rpId":             strings.Split(a.requestHost(r), ":")[0],
			"allowCredentials": allowCredentials,
			"userVerification": "preferred",
			"timeout":          60000,
		},
	})
}

func (a *App) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		ChallengeID       string `json:"challenge_id"`
		CredentialID      string `json:"credential_id"`
		ClientDataJSON    string `json:"client_data_json"`
		AuthenticatorData string `json:"authenticator_data"`
		Signature         string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}
	challenge, err := a.webauthnChallenges.Get(r.Context(), payload.ChallengeID)
	if err != nil || challenge.Operation != "login" || challenge.RemoteAddr != a.clientAddress(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey challenge expired"})
		return
	}
	passkey, err := a.store.GetPanelUserPasskeyByCredentialID(r.Context(), payload.CredentialID)
	if err != nil || passkey.LinuxUser != challenge.Username {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey not found"})
		return
	}
	rpID := strings.Split(a.requestHost(r), ":")[0]
	signCount, err := auth.VerifyWebAuthnAssertion(passkey.PublicKeySPKI, rpID, payload.ClientDataJSON, payload.AuthenticatorData, payload.Signature, challenge.Challenge, a.requestOrigin(r))
	if err != nil {
		a.recordAudit(r.Context(), "auth.login.passkey", challenge.Username, "failure", map[string]any{"error": err.Error()})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey verification failed"})
		return
	}
	if signCount > passkey.SignCount {
		_ = a.store.UpdatePanelUserPasskeySignCount(r.Context(), passkey.ID, signCount)
	}
	identity := auth.Identity{Username: challenge.Username, DisplayName: challenge.Username, AuthProvider: "passkey"}
	a.webauthnChallenges.Delete(r.Context(), challenge.ID)
	if !a.completeAuthenticatedLogin(w, r, identity, "passkey") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/"})
}

func (a *App) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	challenge, err := a.webauthnChallenges.Create(r.Context(), identity.Username, "register", a.clientAddress(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "passkey challenge could not be created"})
		return
	}
	passkeys, _ := a.store.ListPanelUserPasskeys(r.Context(), identity.Username)
	excludeCredentials := make([]map[string]string, 0, len(passkeys))
	for _, passkey := range passkeys {
		excludeCredentials = append(excludeCredentials, map[string]string{"type": "public-key", "id": passkey.CredentialID})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challenge.ID,
		"publicKey": map[string]any{
			"challenge":              challenge.Challenge,
			"rp":                     map[string]string{"name": a.cfg.AppName, "id": strings.Split(a.requestHost(r), ":")[0]},
			"user":                   map[string]string{"id": auth.Base64URLEncode([]byte(identity.Username)), "name": identity.Username, "displayName": firstNonEmpty(identity.DisplayName, identity.Username)},
			"pubKeyCredParams":       []map[string]any{{"type": "public-key", "alg": -7}},
			"authenticatorSelection": map[string]string{"residentKey": "preferred", "userVerification": "preferred"},
			"excludeCredentials":     excludeCredentials,
			"attestation":            "none",
			"timeout":                60000,
		},
	})
}

func (a *App) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	var payload struct {
		ChallengeID    string `json:"challenge_id"`
		CredentialID   string `json:"credential_id"`
		ClientDataJSON string `json:"client_data_json"`
		PublicKeySPKI  string `json:"public_key_spki"`
		Label          string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}
	challenge, err := a.webauthnChallenges.Get(r.Context(), payload.ChallengeID)
	if err != nil || challenge.Operation != "register" || challenge.Username != identity.Username || challenge.RemoteAddr != a.clientAddress(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey challenge expired"})
		return
	}
	clientData, _, err := auth.ParseClientData(payload.ClientDataJSON)
	if err != nil || clientData.Type != "webauthn.create" || clientData.Challenge != challenge.Challenge || strings.TrimSpace(clientData.Origin) != a.requestOrigin(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey registration payload is invalid"})
		return
	}
	if strings.TrimSpace(payload.PublicKeySPKI) == "" || strings.TrimSpace(payload.CredentialID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey public key is missing"})
		return
	}
	if err := a.store.SavePanelUserPasskey(r.Context(), identity.Username, payload.CredentialID, payload.Label, payload.PublicKeySPKI, 0); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "passkey could not be saved"})
		return
	}
	a.webauthnChallenges.Delete(r.Context(), challenge.ID)
	a.recordAudit(r.Context(), "panel.passkey.register", identity.Username, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
	case "sync_repository", "generate_deploy_key", "trust_git_host", "save_auto_deploy", "rotate_auto_deploy_secret":
		return "deploy"
	case "sync_subdomain_repository", "run_subdomain_git_command", "save_subdomain_deploy", "rotate_subdomain_auto_deploy_secret", "move_subdomain_root", "move_subdomain_root_preview", "rollback_subdomain_release", "generate_subdomain_deploy_key", "trust_subdomain_git_host":
		return "domains"
	case "run_custom_git_command":
		return "deploy"
	case "run_ssh_command", "add_ssh_key", "remove_ssh_key", "set_ssh_password":
		return "ssh"
	case "install_nvm", "install_node", "install_pm2", "install_composer", "start_pm2", "restart_pm2", "reload_pm2", "stop_pm2", "run_npm_script", "npm_install", "save_runtime_command", "delete_runtime_command", "save_node_version":
		return "runtime"
	case "enable_tls", "add_subdomain", "delete_subdomain", "enable_subdomain_tls":
		return "domains"
	case "select_dns_zone", "create_dns_record", "update_dns_record", "delete_dns_record", "refresh_dns_records":
		return "dns"
	case "save_backup_config", "run_backup_now":
		return "backups"
	case "assign_database", "assign_linux_user", "save_laravel_extra_writable_paths", "edit_env", "save_nginx_config", "validate_nginx_config", "rollback_nginx_config", "create_cron_job", "update_cron_job", "delete_cron_job", "clear_cron_log", "rotate_cron_log":
		return "settings"
	case "save_site_file", "create_site_file", "chmod_site_file":
		return "files"
	default:
		return "overview"
	}
}

func subdomainDetailTabForAction(action string) string {
	switch action {
	case "sync_subdomain_repository", "run_subdomain_git_command", "save_subdomain_deploy", "rotate_subdomain_auto_deploy_secret", "rollback_subdomain_release", "generate_subdomain_deploy_key", "trust_subdomain_git_host":
		return "deploy"
	case "npm_install", "run_npm_script", "run_custom_command", "install_nvm", "install_node", "install_pm2", "install_composer", "start_pm2", "restart_pm2", "reload_pm2", "stop_pm2", "list_pm2", "show_pm2_logs", "save_runtime_command", "delete_runtime_command", "save_node_version":
		return "runtime"
	case "save_subdomain_file", "create_subdomain_file":
		return "files"
	case "enable_subdomain_tls", "move_subdomain_root", "move_subdomain_root_preview", "save_laravel_extra_writable_paths", "save_nginx_config", "validate_nginx_config", "rollback_nginx_config", "edit_subdomain_env", "delete_subdomain":
		return "settings"
	default:
		return "overview"
	}
}

func autoDeployCommandFromPreset(preset string, processName string, fallback string) string {
	switch strings.TrimSpace(preset) {
	case "pm2_restart":
		if strings.TrimSpace(processName) == "" {
			return fallback
		}
		return "pm2 restart " + shellSingleQuote(strings.TrimSpace(processName))
	case "pm2_reload":
		if strings.TrimSpace(processName) == "" {
			return fallback
		}
		return "pm2 reload " + shellSingleQuote(strings.TrimSpace(processName))
	default:
		return fallback
	}
}

func detectAutoDeployPreset(command string) (string, string) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return "custom", ""
	}
	for _, prefix := range []struct {
		preset string
		value  string
	}{
		{preset: "pm2_restart", value: "pm2 restart "},
		{preset: "pm2_reload", value: "pm2 reload "},
	} {
		if !strings.HasPrefix(trimmed, prefix.value) {
			continue
		}
		processName := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix.value))
		processName = strings.Trim(processName, "'")
		if processName != "" {
			return prefix.preset, processName
		}
	}
	return "custom", ""
}

var panelNodeVersionPattern = regexp.MustCompile(`^(?:lts(?:/[A-Za-z0-9*._-]+)?|node|v?[0-9]+(?:\.[0-9]+){0,2})$`)

func validNodeVersionSelection(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "" || panelNodeVersionPattern.MatchString(trimmed)
}

func mergeNodeVersionOptions(groups ...[]string) []string {
	seen := make(map[string]struct{})
	options := make([]string, 0)
	for _, group := range groups {
		for _, raw := range group {
			value := strings.TrimSpace(raw)
			if value == "" || !validNodeVersionSelection(value) {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			options = append(options, value)
		}
	}
	return options
}

func singleNodeVersionOptions(values ...string) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

func describeCronNextRun(schedule string, now time.Time) string {
	nextRun, err := nextCronRun(schedule, now)
	if err != nil {
		return "Could not estimate"
	}
	until := nextRun.Sub(now)
	if until < 0 {
		until = 0
	}
	return fmt.Sprintf("in %s (%s)", humanizeDuration(until), nextRun.Format("2006-01-02 15:04"))
}

func humanizeDuration(duration time.Duration) string {
	if duration < time.Minute {
		return "under 1 minute"
	}
	minutes := int(duration.Round(time.Minute) / time.Minute)
	days := minutes / (24 * 60)
	minutes -= days * 24 * 60
	hours := minutes / 60
	minutes -= hours * 60
	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if len(parts) == 0 {
		return "under 1 minute"
	}
	return strings.Join(parts, " ")
}

func nextCronRun(schedule string, now time.Time) (time.Time, error) {
	fields, err := normalizeCronFields(schedule)
	if err != nil {
		return time.Time{}, err
	}
	start := now.In(time.Local).Truncate(time.Minute).Add(time.Minute)
	for offset := 0; offset < 366*24*60; offset++ {
		candidate := start.Add(time.Duration(offset) * time.Minute)
		dayOfMonthMatches := cronFieldMatches(fields[2], candidate.Day(), 2)
		dayOfWeekMatches := cronFieldMatches(fields[4], int(candidate.Weekday()), 4)
		if cronFieldMatches(fields[0], candidate.Minute(), 0) &&
			cronFieldMatches(fields[1], candidate.Hour(), 1) &&
			cronFieldMatches(fields[3], int(candidate.Month()), 3) &&
			cronDayMatches(fields[2], fields[4], dayOfMonthMatches, dayOfWeekMatches) {
			return candidate, nil
		}
	}
	return time.Time{}, fmt.Errorf("next run is outside the estimation window")
}

func cronDayMatches(dayOfMonthExpr string, dayOfWeekExpr string, dayOfMonthMatches bool, dayOfWeekMatches bool) bool {
	dayOfMonthWildcard := cronFieldIsWildcard(dayOfMonthExpr)
	dayOfWeekWildcard := cronFieldIsWildcard(dayOfWeekExpr)
	if dayOfMonthWildcard && dayOfWeekWildcard {
		return true
	}
	if dayOfMonthWildcard {
		return dayOfWeekMatches
	}
	if dayOfWeekWildcard {
		return dayOfMonthMatches
	}
	return dayOfMonthMatches || dayOfWeekMatches
}

func cronFieldIsWildcard(expression string) bool {
	return strings.TrimSpace(expression) == "*"
}

func normalizeCronFields(schedule string) ([]string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(schedule))
	switch trimmed {
	case "@yearly", "@annually":
		return []string{"0", "0", "1", "1", "*"}, nil
	case "@monthly":
		return []string{"0", "0", "1", "*", "*"}, nil
	case "@weekly":
		return []string{"0", "0", "*", "*", "0"}, nil
	case "@daily", "@midnight":
		return []string{"0", "0", "*", "*", "*"}, nil
	case "@hourly":
		return []string{"0", "*", "*", "*", "*"}, nil
	case "@reboot":
		return nil, fmt.Errorf("@reboot does not have a predictable next run time")
	}
	parts := strings.Fields(trimmed)
	if len(parts) != 5 {
		return nil, fmt.Errorf("unsupported cron expression")
	}
	return parts, nil
}

func cronFieldMatches(expression string, value int, fieldIndex int) bool {
	minValue, maxValue := cronFieldBounds(fieldIndex)
	for _, part := range strings.Split(expression, ",") {
		if cronPartMatches(strings.TrimSpace(part), value, minValue, maxValue, fieldIndex == 4) {
			return true
		}
	}
	return false
}

func cronFieldBounds(fieldIndex int) (int, int) {
	switch fieldIndex {
	case 0:
		return 0, 59
	case 1:
		return 0, 23
	case 2:
		return 1, 31
	case 3:
		return 1, 12
	case 4:
		return 0, 7
	default:
		return 0, 0
	}
}

func cronPartMatches(part string, value int, minValue int, maxValue int, dayOfWeek bool) bool {
	if part == "" {
		return false
	}
	if dayOfWeek && value == 0 {
		if part == "7" || strings.HasPrefix(part, "7,") || strings.Contains(part, ",7") || strings.Contains(part, "-7") {
			return true
		}
	}
	if part == "*" {
		return true
	}
	step := 1
	base := part
	if strings.Contains(part, "/") {
		pieces := strings.SplitN(part, "/", 2)
		base = strings.TrimSpace(pieces[0])
		parsedStep, err := strconv.Atoi(strings.TrimSpace(pieces[1]))
		if err != nil || parsedStep <= 0 {
			return false
		}
		step = parsedStep
	}
	start, end, ok := cronRangeBounds(base, minValue, maxValue, dayOfWeek)
	if !ok || value < start || value > end {
		return false
	}
	return (value-start)%step == 0
}

func cronRangeBounds(base string, minValue int, maxValue int, dayOfWeek bool) (int, int, bool) {
	base = strings.TrimSpace(base)
	if base == "" || base == "*" {
		return minValue, maxValue, true
	}
	parseValue := func(raw string) (int, error) {
		parsed, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return 0, err
		}
		if dayOfWeek && parsed == 7 {
			return 0, nil
		}
		return parsed, nil
	}
	if strings.Contains(base, "-") {
		parts := strings.SplitN(base, "-", 2)
		start, errStart := parseValue(parts[0])
		end, errEnd := parseValue(parts[1])
		if errStart != nil || errEnd != nil || start > end {
			return 0, 0, false
		}
		return start, end, true
	}
	parsed, err := parseValue(base)
	if err != nil {
		return 0, 0, false
	}
	return parsed, parsed, true
}

func isAllowedNginxConfigPath(baseDir string, configPath string) bool {
	baseDir = filepath.Clean(strings.TrimSpace(baseDir))
	configPath = filepath.Clean(strings.TrimSpace(configPath))
	if baseDir == "" || configPath == "" || !filepath.IsAbs(baseDir) || !filepath.IsAbs(configPath) {
		return false
	}
	return configPath == baseDir || strings.HasPrefix(configPath, baseDir+string(os.PathSeparator))
}

func resolveNginxConfigTarget(site domain.ManagedSite, subdomains []domain.SiteSubdomain, targetType string, targetID int64) (string, string, string, int64, error) {
	targetType = strings.TrimSpace(targetType)
	switch targetType {
	case "", "site":
		if strings.TrimSpace(site.NginxConfigPath) == "" {
			return "", "", "", 0, errors.New("this site does not have a stored Nginx config path")
		}
		return site.NginxConfigPath, site.Name, site.DomainName, 0, nil
	case "subdomain":
		for _, subdomain := range subdomains {
			if subdomain.ID == targetID {
				if strings.TrimSpace(subdomain.NginxConfigPath) == "" {
					return "", "", "", 0, errors.New("selected subdomain does not have a stored Nginx config path")
				}
				return subdomain.NginxConfigPath, subdomain.FullDomain, subdomain.FullDomain, subdomain.ID, nil
			}
		}
		return "", "", "", 0, errors.New("subdomain config target could not be found")
	default:
		return "", "", "", 0, errors.New("invalid Nginx config target type")
	}
}

func (a *App) saveNginxConfigContent(ctx context.Context, site domain.ManagedSite, subdomainID int64, configPath string, content string, createRevision bool) error {
	var previousConfig string
	_, _ = a.helper.Call(ctx, "files.read_text", map[string]any{"path": configPath, "max_bytes": 1048576}, &previousConfig)
	if createRevision && a.store != nil && previousConfig != "" && previousConfig != content {
		_, _ = a.store.CreateNginxConfigRevision(ctx, domain.NginxConfigRevision{SiteID: site.ID, SubdomainID: subdomainID, ConfigPath: configPath, Content: previousConfig})
	}
	if _, err := a.helper.Call(ctx, "nginx.write_config", map[string]string{"path": configPath, "content": content}, nil); err != nil {
		return fmt.Errorf("could not write Nginx config: %w", err)
	}
	if err := a.nginx.ValidateConfig(configPath); err != nil {
		_, _ = a.helper.Call(ctx, "nginx.write_config", map[string]string{"path": configPath, "content": previousConfig}, nil)
		return fmt.Errorf("Nginx config validation failed, previous config was restored: %w", err)
	}
	if err := a.nginx.Reload(); err != nil {
		_, _ = a.helper.Call(ctx, "nginx.write_config", map[string]string{"path": configPath, "content": previousConfig}, nil)
		_ = a.nginx.ValidateConfig(configPath)
		_ = a.nginx.Reload()
		return fmt.Errorf("Nginx reload failed, previous config was restored: %w", err)
	}
	return nil
}

func resolveSiteBrowserPath(rootDir string, requested string) (string, string, error) {
	rootDir = filepath.Clean(strings.TrimSpace(rootDir))
	requested = strings.TrimSpace(requested)
	if rootDir == "" || !filepath.IsAbs(rootDir) {
		return "", "", errors.New("invalid site root")
	}
	relPath := ""
	if requested != "" {
		relPath = strings.TrimPrefix(filepath.Clean("/"+requested), "/")
		if relPath == "." {
			relPath = ""
		}
	}
	absPath := filepath.Join(rootDir, relPath)
	relCheck, err := filepath.Rel(rootDir, absPath)
	if err != nil {
		return "", "", err
	}
	if relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
		return "", "", errors.New("path is outside the site root")
	}
	if relPath == "." {
		relPath = ""
	}
	return absPath, relPath, nil
}

func parentRelativePath(relPath string) string {
	relPath = strings.TrimSpace(relPath)
	if relPath == "" {
		return ""
	}
	parent := filepath.Dir(relPath)
	if parent == "." {
		return ""
	}
	return parent
}

type helperSiteFileEntry struct {
	Name          string `json:"name"`
	IsDir         bool   `json:"is_dir"`
	Size          int64  `json:"size"`
	IsSymlink     bool   `json:"is_symlink"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
	Mode          string `json:"mode"`
	Owner         string `json:"owner"`
}

func (a *App) detectProjectMarkers(ctx context.Context, rootDirectory string) (bool, bool) {
	rootDirectory = strings.TrimSpace(rootDirectory)
	if rootDirectory == "" {
		return false, false
	}
	var entries []helperSiteFileEntry
	if _, err := a.helper.Call(ctx, "files.list_dir", map[string]string{"path": rootDirectory}, &entries); err != nil {
		return false, false
	}
	hasComposer := false
	hasArtisan := false
	hasPublicDir := false
	hasBootstrapDir := false
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if entry.IsDir {
			switch name {
			case "public":
				hasPublicDir = true
			case "bootstrap":
				hasBootstrapDir = true
			}
			continue
		}
		switch name {
		case "composer.json":
			hasComposer = true
		case "artisan":
			hasArtisan = true
		}
	}
	if !(hasComposer && hasArtisan && hasPublicDir && hasBootstrapDir) {
		return hasComposer, false
	}
	publicHasIndex := false
	bootstrapHasApp := false
	if hasPublicDir {
		var publicEntries []helperSiteFileEntry
		if _, err := a.helper.Call(ctx, "files.list_dir", map[string]string{"path": filepath.Join(rootDirectory, "public")}, &publicEntries); err == nil {
			for _, entry := range publicEntries {
				if !entry.IsDir && strings.TrimSpace(entry.Name) == "index.php" {
					publicHasIndex = true
					break
				}
			}
		}
	}
	if hasBootstrapDir {
		var bootstrapEntries []helperSiteFileEntry
		if _, err := a.helper.Call(ctx, "files.list_dir", map[string]string{"path": filepath.Join(rootDirectory, "bootstrap")}, &bootstrapEntries); err == nil {
			for _, entry := range bootstrapEntries {
				if !entry.IsDir && strings.TrimSpace(entry.Name) == "app.php" {
					bootstrapHasApp = true
					break
				}
			}
		}
	}
	return hasComposer, publicHasIndex && bootstrapHasApp
}

func recommendedDeployCommand(hasComposer bool, hasLaravel bool, packageScripts []string, processName string) string {
	processName = strings.TrimSpace(processName)
	if hasLaravel {
		return "composer install --no-dev --optimize-autoloader && php artisan migrate --force && php artisan optimize"
	}
	if len(packageScripts) > 0 {
		if processName != "" {
			return "npm ci && npm run build && pm2 reload " + processName
		}
		return "npm ci && npm run build"
	}
	if hasComposer {
		return "composer install --no-dev --optimize-autoloader"
	}
	if processName != "" {
		return "Optional command after deploy, for example pm2 reload " + processName
	}
	return "Optional command after deploy"
}

type subdomainMovePreview struct {
	From          string
	To            string
	TargetExists  bool
	TargetEmpty   bool
	TargetGitRepo bool
	TargetState   string
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

func requestExternalBaseURL(r *http.Request, fallbackBaseURL string) string {
	fallbackBaseURL = strings.TrimSpace(fallbackBaseURL)
	if r == nil || strings.TrimSpace(r.Host) == "" {
		return fallbackBaseURL
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	} else if fallbackBaseURL != "" {
		if parsed, err := url.Parse(fallbackBaseURL); err == nil && parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
	}
	return scheme + "://" + strings.TrimSpace(r.Host)
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

func sanitizeSubdomainDirectoryName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var buffer []rune
	lastSeparator := false
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			buffer = append(buffer, ch)
			lastSeparator = false
		case ch == '-', ch == '_', ch == '.':
			if len(buffer) == 0 || lastSeparator {
				continue
			}
			buffer = append(buffer, '-')
			lastSeparator = true
		}
	}
	return strings.Trim(string(buffer), "-. ")
}

func buildManagedSubdomainRootDirectory(site domain.ManagedSite, baseDirectory string, directoryName string) string {
	directoryName = sanitizeSubdomainDirectoryName(directoryName)
	if directoryName == "" {
		directoryName = sanitizeSubdomainDirectoryName(site.Name + "-subdomain")
	}
	baseDirectory = strings.TrimSpace(baseDirectory)
	if baseDirectory == "" {
		baseDirectory = filepath.Dir(filepath.Clean(strings.TrimSpace(site.RootDirectory)))
	}
	if baseDirectory == "." || baseDirectory == "/" || baseDirectory == "" {
		baseDirectory = filepath.Join("/home", strings.TrimSpace(site.OwnerLinuxUser))
	}
	return filepath.Join(baseDirectory, directoryName)
}

func buildSiteSubdomain(site domain.ManagedSite, baseDirectory string, label string, mode string, upstreamURL string, phpVersion string, directoryName string) (domain.SiteSubdomain, system.SiteSpec, error) {
	label = sanitizeSubdomainLabel(label)
	if label == "" {
		return domain.SiteSubdomain{}, system.SiteSpec{}, errors.New("Subdomain label is required.")
	}
	fullDomain := label + "." + strings.TrimSpace(site.DomainName)
	mode = firstNonEmpty(strings.TrimSpace(mode), "reverse_proxy")
	rootDirectory := buildManagedSubdomainRootDirectory(site, baseDirectory, firstNonEmpty(strings.TrimSpace(directoryName), label))
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

func findSiteSubdomain(items []domain.SiteSubdomain, subdomainID int64) (domain.SiteSubdomain, bool) {
	for _, item := range items {
		if item.ID == subdomainID {
			return item, true
		}
	}
	return domain.SiteSubdomain{}, false
}

func buildSubdomainAutoDeployWebhookURL(baseURL string, siteName string, subdomainID int64, secret string) string {
	baseURL = strings.TrimSpace(baseURL)
	siteName = strings.TrimSpace(siteName)
	secret = strings.TrimSpace(secret)
	if baseURL == "" || siteName == "" || secret == "" || subdomainID <= 0 {
		return ""
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	parsed.Path = "/webhooks/site-deploy"
	query := parsed.Query()
	query.Set("site", siteName)
	query.Set("subdomain_id", strconv.FormatInt(subdomainID, 10))
	query.Set("secret", secret)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func shellSingleQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func buildSubdomainSiteSpec(site domain.ManagedSite, subdomain domain.SiteSubdomain, rootDirectory string) system.SiteSpec {
	rootDirectory = firstNonEmpty(strings.TrimSpace(rootDirectory), subdomain.RootDirectory)
	return system.SiteSpec{
		Name:           subdomainConfigName(site.Name, subdomain.FullDomain),
		OwnerLinuxUser: site.OwnerLinuxUser,
		Domain:         subdomain.FullDomain,
		Mode:           subdomain.Runtime,
		RootDirectory:  rootDirectory,
		UpstreamURL:    subdomain.UpstreamURL,
		PHPVersion:     subdomain.PHPVersion,
	}
}

func (a *App) inspectSubdomainMovePreview(ctx context.Context, site domain.ManagedSite, subdomain domain.SiteSubdomain, directoryName string) subdomainMovePreview {
	preview := subdomainMovePreview{
		From: subdomain.RootDirectory,
		To:   buildManagedSubdomainRootDirectory(site, a.cfg.SubdomainRootBaseDir, firstNonEmpty(directoryName, subdomain.Subdomain)),
	}
	status, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: preview.To, RunAsUser: site.OwnerLinuxUser})
	if inspectErr == nil {
		preview.TargetExists = status.DirectoryExists
		preview.TargetGitRepo = status.IsGitRepo
	}
	var entries []helperSiteFileEntry
	if _, err := a.helper.Call(ctx, "files.list_dir", map[string]string{"path": preview.To}, &entries); err == nil {
		preview.TargetExists = true
		preview.TargetEmpty = len(entries) == 0
	} else if !preview.TargetExists {
		preview.TargetState = "Target does not exist yet."
	}
	if preview.TargetExists {
		switch {
		case preview.TargetGitRepo:
			preview.TargetState = "Target exists and already contains a git repository."
		case preview.TargetEmpty:
			preview.TargetState = "Target exists and is empty."
		default:
			preview.TargetState = "Target exists and is not empty."
		}
	}
	return preview
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
	subdomainID, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("subdomain_id")), 10, 64)
	targetName := site.Name
	targetDirectory := site.RootDirectory
	targetBranch := strings.TrimSpace(site.AutoDeployBranch)
	targetSecret := strings.TrimSpace(site.AutoDeploySecret)
	targetCommand := strings.TrimSpace(site.AutoDeployCommand)
	targetNodeVersion := firstNonEmpty(strings.TrimSpace(site.AutoDeployNodeVersion), strings.TrimSpace(site.NodeVersion))
	targetNotifyEmail := strings.TrimSpace(site.AutoDeployNotifyEmail)
	autoDeployEnabled := site.AutoDeployEnabled
	var webhookSubdomain domain.SiteSubdomain
	if subdomainID > 0 {
		subdomains, listErr := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if listErr != nil {
			http.Error(w, "subdomain lookup failed", http.StatusInternalServerError)
			return
		}
		var ok bool
		webhookSubdomain, ok = findSiteSubdomain(subdomains, subdomainID)
		if !ok {
			http.Error(w, "subdomain not found", http.StatusNotFound)
			return
		}
		targetName = webhookSubdomain.FullDomain
		targetDirectory = webhookSubdomain.RootDirectory
		targetBranch = firstNonEmpty(webhookSubdomain.AutoDeployBranch, webhookSubdomain.BranchName)
		targetSecret = strings.TrimSpace(webhookSubdomain.AutoDeploySecret)
		targetCommand = strings.TrimSpace(webhookSubdomain.AutoDeployCommand)
		targetNodeVersion = firstNonEmpty(strings.TrimSpace(webhookSubdomain.AutoDeployNodeVersion), strings.TrimSpace(webhookSubdomain.NodeVersion))
		targetNotifyEmail = strings.TrimSpace(webhookSubdomain.AutoDeployNotifyEmail)
		autoDeployEnabled = webhookSubdomain.AutoDeployEnabled
	}
	if !autoDeployEnabled || targetSecret == "" {
		a.recordAudit(r.Context(), "deploy.webhook", targetName, "failure", map[string]any{"reason": "auto_deploy_disabled", "subdomain_id": subdomainID})
		http.Error(w, "auto deploy disabled", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	authMode, ok := verifyWebhookSecret(r, body, targetSecret)
	if !ok {
		a.recordAudit(r.Context(), "deploy.webhook", targetName, "failure", map[string]any{"reason": "invalid_secret", "auth_mode": authMode, "subdomain_id": subdomainID})
		http.Error(w, "invalid secret", http.StatusForbidden)
		return
	}
	incomingBranch := buildWebhookBranch(body)
	provider := firstNonEmpty(strings.TrimSpace(r.Header.Get("X-GitHub-Event")), strings.TrimSpace(r.Header.Get("X-Gitlab-Event")), strings.TrimSpace(r.Header.Get("X-Gitea-Event")), "generic")
	configuredBranch := targetBranch
	if incomingBranch != "" && configuredBranch != "" && incomingBranch != configuredBranch {
		a.recordAudit(r.Context(), "deploy.webhook", targetName, "ignored", map[string]any{"reason": "branch_mismatch", "incoming_branch": incomingBranch, "branch": configuredBranch, "provider": provider, "auth_mode": authMode, "subdomain_id": subdomainID})
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "ignored", "reason": "branch_mismatch", "branch": incomingBranch})
		return
	}
	repositoryStatus, inspectErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: targetDirectory, RunAsUser: site.OwnerLinuxUser})
	if inspectErr != nil || strings.TrimSpace(repositoryStatus.RemoteURL) == "" {
		a.recordAudit(r.Context(), "deploy.webhook", targetName, "failure", map[string]any{"reason": "repository_not_ready", "provider": provider, "auth_mode": authMode, "subdomain_id": subdomainID})
		http.Error(w, "site repository is not ready for auto deploy", http.StatusPreconditionFailed)
		return
	}
	a.recordAudit(r.Context(), "deploy.webhook", targetName, "queued", map[string]any{"branch": configuredBranch, "incoming_branch": incomingBranch, "provider": provider, "auth_mode": authMode, "subdomain_id": subdomainID})
	go func(site domain.ManagedSite, subdomain domain.SiteSubdomain, repositoryURL string, branch string, targetLabel string, deployDirectory string, notifyEmail string, postDeployCommand string, postDeployNodeVersion string, subdomainID int64) {
		ctx := context.Background()
		gitSiteName := site.Name
		if subdomainID > 0 {
			gitSiteName = subdomain.FullDomain
		}
		result, deployErr := a.deploys.Deploy(system.DeploySpec{
			RepositoryURL:         repositoryURL,
			Branch:                branch,
			TargetDirectory:       deployDirectory,
			RunAsUser:             site.OwnerLinuxUser,
			GitSiteName:           gitSiteName,
			PostDeployCommand:     postDeployCommand,
			PostDeployNodeVersion: postDeployNodeVersion,
		})
		notifySite := site
		notifySite.Name = targetLabel
		if subdomainID > 0 {
			notifySite.DomainName = subdomain.FullDomain
		}
		notifySite.AutoDeployNotifyEmail = notifyEmail
		if deployErr != nil {
			if a.store != nil {
				_ = a.store.CreateDeployment(ctx, domain.Deployment{SiteID: site.ID, RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: deployDirectory, RunAsUser: site.OwnerLinuxUser, LastStatus: "failure", LastOutput: result.Output})
				_ = a.store.CreateDeploymentRelease(ctx, domain.DeploymentRelease{RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: deployDirectory, RunAsUser: site.OwnerLinuxUser, Action: firstNonEmpty(result.Action, "deploy"), Status: "failure", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output})
			}
			a.recordAudit(ctx, "deploy.webhook", targetLabel, "failure", map[string]any{"branch": branch, "error": deployErr.Error(), "provider": provider, "auth_mode": authMode, "subdomain_id": subdomainID})
			_ = sendAutoDeployResultEmail(a.cfg, notifySite, branch, domain.DeploymentRelease{RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: deployDirectory, RunAsUser: site.OwnerLinuxUser, Action: firstNonEmpty(result.Action, "deploy"), Status: "failure", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output}, deployErr)
			return
		}
		if a.store != nil {
			_ = a.store.CreateDeployment(ctx, domain.Deployment{SiteID: site.ID, RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: deployDirectory, RunAsUser: site.OwnerLinuxUser, LastStatus: "success", LastOutput: result.Output})
			_ = a.store.CreateDeploymentRelease(ctx, domain.DeploymentRelease{RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: deployDirectory, RunAsUser: site.OwnerLinuxUser, Action: result.Action, Status: "success", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output})
		}
		metadata := map[string]any{"branch": branch, "action": result.Action, "provider": provider, "auth_mode": authMode, "subdomain_id": subdomainID}
		if incomingBranch != "" {
			metadata["incoming_branch"] = incomingBranch
		}
		a.recordAudit(ctx, "deploy.webhook", targetLabel, "success", metadata)
		_ = sendAutoDeployResultEmail(a.cfg, notifySite, branch, domain.DeploymentRelease{RepositoryURL: repositoryURL, BranchName: branch, TargetDirectory: deployDirectory, RunAsUser: site.OwnerLinuxUser, Action: result.Action, Status: "success", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output}, nil)
	}(site, webhookSubdomain, repositoryStatus.RemoteURL, configuredBranch, targetName, targetDirectory, targetNotifyEmail, targetCommand, targetNodeVersion, subdomainID)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "queued", "site": targetName, "branch": configuredBranch, "subdomain_id": subdomainID})
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
	password := r.FormValue("linux_password")
	grantSudo := r.FormValue("grant_sudo") == "1"
	grantPasswordlessSudo := r.FormValue("grant_passwordless_sudo") == "1"
	if err := a.users.CreateLinuxUser(username, createHome, password, grantSudo); err != nil {
		a.recordAudit(r.Context(), "user.create", username, "failure", map[string]any{"create_home": createHome, "error": err.Error()})
		message := err.Error()
		if errors.Is(err, system.ErrInvalidUsername) {
			message = "Username format is invalid for Ubuntu user creation."
		}
		if errors.Is(err, system.ErrUserExists) {
			message = "That Linux user already exists on the host."
		}
		if errors.Is(err, system.ErrInvalidLinuxPassword) {
			message = "Linux password is invalid. Do not use empty values, new lines, or colons."
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
	if grantPasswordlessSudo {
		if err := a.users.SetLinuxUserPasswordlessSudo(username, true); err != nil {
			a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{Title: "Users", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), LinuxUsers: updatedUsers, RequestError: err.Error()})
			return
		}
		updatedUsers, _ = a.users.ListLinuxUsers()
	}
	a.recordAudit(r.Context(), "user.create", username, "success", map[string]any{"create_home": createHome, "grant_sudo": grantSudo})
	a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{
		Title:          "Users",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     updatedUsers,
		SuccessMessage: "Linux user was created successfully.",
	})
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request, users []system.LinuxUser) {
	action := r.FormValue("user_action")
	if action == "set_password" {
		a.handleUserPasswordUpdate(w, r, users)
		return
	}
	if action == "set_sudo" {
		a.handleUserSudoUpdate(w, r, users)
		return
	}
	if action == "set_passwordless_sudo" {
		a.handleUserPasswordlessSudoUpdate(w, r, users)
		return
	}
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

func (a *App) handleUserPasswordUpdate(w http.ResponseWriter, r *http.Request, users []system.LinuxUser) {
	username := strings.TrimSpace(r.FormValue("password_username"))
	password := r.FormValue("set_linux_password")
	if err := a.users.SetLinuxUserPassword(username, password); err != nil {
		a.recordAudit(r.Context(), "user.set_password", username, "failure", map[string]any{"error": err.Error()})
		message := err.Error()
		switch {
		case errors.Is(err, system.ErrInvalidUsername):
			message = "Linux username format is invalid."
		case errors.Is(err, system.ErrUserNotFound):
			message = "Linux user could not be found."
		case errors.Is(err, system.ErrInvalidLinuxPassword):
			message = "Linux password is invalid. Do not use empty values, new lines, or colons."
		}
		a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{Title: "Users", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), LinuxUsers: users, RequestError: message})
		return
	}
	updatedUsers, _ := a.users.ListLinuxUsers()
	a.recordAudit(r.Context(), "user.set_password", username, "success", nil)
	a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{Title: "Users", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), LinuxUsers: updatedUsers, SuccessMessage: "Linux user password was updated successfully."})
}

func (a *App) handleUserSudoUpdate(w http.ResponseWriter, r *http.Request, users []system.LinuxUser) {
	username := strings.TrimSpace(r.FormValue("sudo_username"))
	enabled := r.FormValue("sudo_enabled") == "1"
	if err := a.users.SetLinuxUserSudo(username, enabled); err != nil {
		a.recordAudit(r.Context(), "user.set_sudo", username, "failure", map[string]any{"enabled": enabled, "error": err.Error()})
		message := err.Error()
		switch {
		case errors.Is(err, system.ErrInvalidUsername):
			message = "Linux username format is invalid."
		case errors.Is(err, system.ErrUserNotFound):
			message = "Linux user could not be found."
		case errors.Is(err, system.ErrProtectedUser):
			message = "This Linux user is protected and cannot have sudo changed from the panel."
		}
		a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{Title: "Users", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), LinuxUsers: users, RequestError: message})
		return
	}
	updatedUsers, _ := a.users.ListLinuxUsers()
	a.recordAudit(r.Context(), "user.set_sudo", username, "success", map[string]any{"enabled": enabled})
	message := "Sudo access was revoked successfully."
	if enabled {
		message = "Sudo access was granted successfully."
	}
	a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{Title: "Users", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), LinuxUsers: updatedUsers, SuccessMessage: message})
}

func (a *App) handleUserPasswordlessSudoUpdate(w http.ResponseWriter, r *http.Request, users []system.LinuxUser) {
	username := strings.TrimSpace(r.FormValue("passwordless_sudo_username"))
	enabled := r.FormValue("passwordless_sudo_enabled") == "1"
	if err := a.users.SetLinuxUserPasswordlessSudo(username, enabled); err != nil {
		a.recordAudit(r.Context(), "user.set_passwordless_sudo", username, "failure", map[string]any{"enabled": enabled, "error": err.Error()})
		message := err.Error()
		switch {
		case errors.Is(err, system.ErrInvalidUsername):
			message = "Linux username format is invalid."
		case errors.Is(err, system.ErrUserNotFound):
			message = "Linux user could not be found."
		case errors.Is(err, system.ErrProtectedUser):
			message = "This Linux user is protected and cannot have passwordless sudo changed from the panel."
		}
		a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{Title: "Users", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), LinuxUsers: users, RequestError: message})
		return
	}
	updatedUsers, _ := a.users.ListLinuxUsers()
	a.recordAudit(r.Context(), "user.set_passwordless_sudo", username, "success", map[string]any{"enabled": enabled})
	message := "Passwordless sudo was disabled successfully."
	if enabled {
		message = "Passwordless sudo was enabled successfully."
	}
	a.render(r.Context(), w, r.URL.Path, "users.html", TemplateData{Title: "Users", DatabaseStatus: a.databaseStatus(r.Context()), Metrics: a.metrics.Snapshot(), LinuxUsers: updatedUsers, SuccessMessage: message})
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
		if err := r.ParseMultipartForm(a.cfg.DatabaseRestoreMaxBytes); err != nil {
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
			tempPath, restoreSQL, err := writeDatabaseRestoreTempFile(r, a.cfg.DatabaseRestoreMaxBytes)
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

func writeDatabaseRestoreTempFile(r *http.Request, maxRestoreBytes int64) (string, string, error) {
	if maxRestoreBytes <= 0 {
		maxRestoreBytes = 64 << 20
	}
	maxRestoreMB := maxRestoreBytes / (1 << 20)
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
		if int64(len(content)) > maxRestoreBytes {
			return "", "", fmt.Errorf("Restore file is too large. Maximum supported size is %d MB.", maxRestoreMB)
		}
		sqlContent = string(content)
	}
	if strings.TrimSpace(sqlContent) == "" {
		return "", "", errors.New("Restore content cannot be empty.")
	}
	if int64(len(sqlContent)) > maxRestoreBytes {
		return "", sqlContent, fmt.Errorf("Restore SQL is too large. Maximum supported size is %d MB.", maxRestoreMB)
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

func (a *App) handleMySQLService(w http.ResponseWriter, r *http.Request) {
	entries, listErr := a.databases.ListDatabaseAccess()
	if listErr != nil {
		entries = nil
	}
	status, inspectErr := a.databases.InspectService()
	data := a.mysqlServiceTemplateData(r, status, entries)
	if inspectErr != nil {
		data.RequestError = "MySQL service status could not be loaded: " + mysqlServiceErrorMessage(inspectErr)
	}

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "mysql_service.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		data.RequestError = "The submitted MySQL form could not be parsed."
		a.render(r.Context(), w, r.URL.Path, "mysql_service.html", data)
		return
	}

	data.MySQLMaxConnections = firstNonEmpty(strings.TrimSpace(r.FormValue("max_connections")), data.MySQLMaxConnections)
	data.MySQLMaxUserConnections = firstNonEmpty(strings.TrimSpace(r.FormValue("max_user_connections")), data.MySQLMaxUserConnections)
	data.MySQLWaitTimeout = firstNonEmpty(strings.TrimSpace(r.FormValue("wait_timeout")), data.MySQLWaitTimeout)
	data.MySQLInteractiveTimeout = firstNonEmpty(strings.TrimSpace(r.FormValue("interactive_timeout")), data.MySQLInteractiveTimeout)
	data.MySQLMaxConnectErrors = firstNonEmpty(strings.TrimSpace(r.FormValue("max_connect_errors")), data.MySQLMaxConnectErrors)
	data.MySQLThreadCacheSize = firstNonEmpty(strings.TrimSpace(r.FormValue("thread_cache_size")), data.MySQLThreadCacheSize)
	data.MySQLTableOpenCache = firstNonEmpty(strings.TrimSpace(r.FormValue("table_open_cache")), data.MySQLTableOpenCache)
	data.MySQLInnodbBufferPoolSizeMB = firstNonEmpty(strings.TrimSpace(r.FormValue("innodb_buffer_pool_size_mb")), data.MySQLInnodbBufferPoolSizeMB)
	data.MySQLPort = firstNonEmpty(strings.TrimSpace(r.FormValue("mysql_port")), data.MySQLPort)
	data.MySQLBindAddress = firstNonEmpty(strings.TrimSpace(r.FormValue("mysql_bind_address")), data.MySQLBindAddress)
	data.MySQLSlowQueryLogEnabled = r.FormValue("mysql_slow_query_log_enabled") == "1"
	data.MySQLSlowQueryLogFile = firstNonEmpty(strings.TrimSpace(r.FormValue("mysql_slow_query_log_file")), data.MySQLSlowQueryLogFile)
	data.MySQLLongQueryTime = firstNonEmpty(strings.TrimSpace(r.FormValue("mysql_long_query_time")), data.MySQLLongQueryTime)
	data.MySQLAdminQuery = strings.TrimSpace(r.FormValue("mysql_admin_query"))
	refreshData := func() {
		if refreshedEntries, err := a.databases.ListDatabaseAccess(); err == nil {
			data.DatabaseAccess = refreshedEntries
		}
		if refreshedStatus, err := a.databases.InspectService(); err == nil {
			data.MySQLServiceStatus = refreshedStatus
		}
	}

	if serviceAIAction := strings.TrimSpace(r.FormValue("service_ai_action")); serviceAIAction != "" {
		switch serviceAIAction {
		case "analyze":
			result, err := a.requestServiceAIRecommendation(r.Context(), "mysql", mysqlAIRecommendationSnapshot(status, entries), true)
			if err != nil {
				data.RequestError = err.Error()
				a.recordAudit(r.Context(), "mysql.ai.analyze", status.ServiceName, "failure", map[string]any{"error": err.Error()})
				break
			}
			applyAIRecommendation(&data, result)
			data.SuccessMessage = "OpenAI recommendations loaded successfully."
			a.recordAudit(r.Context(), "mysql.ai.analyze", status.ServiceName, "success", nil)
		case "apply_mysql_ai":
			spec, err := mysqlAIConfigSpecFromForm(r.FormValue)
			if err != nil {
				data.RequestError = err.Error()
				break
			}
			applyMySQLServiceConfigToTemplateData(&data, spec)
			output, err := a.databases.ConfigureService(spec)
			data.CommandOutput = output
			if err != nil {
				data.RequestError = mysqlServiceErrorMessage(err)
				a.recordAudit(r.Context(), "mysql.ai.apply", status.ServiceName, "failure", map[string]any{"error": err.Error()})
				break
			}
			data.SuccessMessage = "OpenAI suggested MySQL settings were saved successfully. Restart the service to apply persistent changes."
			data.MySQLAISuggestionReady = false
			data.MySQLAISuggestedConfig = system.MySQLServiceConfigSpec{}
			data.MySQLAIPreviewChanges = nil
			a.recordAudit(r.Context(), "mysql.ai.apply", status.ServiceName, "success", map[string]any{"max_connections": spec.MaxConnections, "port": spec.Port})
		default:
			data.RequestError = "Invalid OpenAI action."
		}
		refreshData()
		a.render(r.Context(), w, r.URL.Path, "mysql_service.html", data)
		return
	}

	action := strings.TrimSpace(r.FormValue("mysql_action"))
	switch action {
	case "install_service":
		output, err := a.databases.InstallService()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "MySQL service could not be installed: " + mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.install_service", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "MySQL service was installed successfully."
		a.recordAudit(r.Context(), "mysql.install_service", status.ServiceName, "success", nil)
	case "upgrade_service":
		output, err := a.databases.UpgradeService()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "MySQL service could not be upgraded: " + mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.upgrade_service", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "MySQL service was upgraded successfully."
		a.recordAudit(r.Context(), "mysql.upgrade_service", status.ServiceName, "success", nil)
	case "save_config":
		spec, err := mysqlServiceConfigSpecFromForm(data)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		output, err := a.databases.ConfigureService(spec)
		data.CommandOutput = output
		if err != nil {
			data.RequestError = mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.configure_service", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "MySQL settings were saved successfully. Restart the service to apply persistent changes."
		a.recordAudit(r.Context(), "mysql.configure_service", status.ServiceName, "success", map[string]any{"max_connections": spec.MaxConnections, "max_user_connections": spec.MaxUserConnections, "port": spec.Port, "bind_address": spec.BindAddress, "slow_query_log_enabled": spec.SlowQueryLogEnabled})
	case "start_service":
		output, err := a.databases.StartService()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "MySQL service could not be started: " + mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.start_service", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "MySQL service started successfully."
		a.recordAudit(r.Context(), "mysql.start_service", status.ServiceName, "success", nil)
	case "stop_service":
		output, err := a.databases.StopService()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "MySQL service could not be stopped: " + mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.stop_service", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "MySQL service stopped successfully."
		a.recordAudit(r.Context(), "mysql.stop_service", status.ServiceName, "success", nil)
	case "restart_service":
		output, err := a.databases.RestartService()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "MySQL service could not be restarted: " + mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.restart_service", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "MySQL service restarted successfully."
		a.recordAudit(r.Context(), "mysql.restart_service", status.ServiceName, "success", nil)
	case "enable_remote", "disable_remote":
		if action == "enable_remote" {
			data.MySQLBindAddress = "0.0.0.0"
		} else {
			data.MySQLBindAddress = "127.0.0.1"
		}
		spec, err := mysqlServiceConfigSpecFromForm(data)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		output, err := a.databases.ConfigureService(spec)
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Could not update bind address: " + mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.remote_access", status.ServiceName, "failure", map[string]any{"action": action, "error": err.Error()})
			break
		}
		restartOutput, restartErr := a.databases.RestartService()
		data.CommandOutput += restartOutput
		if restartErr != nil {
			data.RequestError = "Bind address saved but service restart failed: " + mysqlServiceErrorMessage(restartErr)
			a.recordAudit(r.Context(), "mysql.remote_access", status.ServiceName, "failure", map[string]any{"action": action, "error": restartErr.Error()})
			break
		}
		data.MySQLRemoteAccessEnabled = action == "enable_remote"
		if action == "enable_remote" {
			data.SuccessMessage = "Remote access enabled. MySQL now listens on all interfaces (0.0.0.0). Ensure your firewall allows port " + data.MySQLPort + "."
		} else {
			data.SuccessMessage = "Remote access disabled. MySQL now only accepts local connections."
		}
		a.recordAudit(r.Context(), "mysql.remote_access", status.ServiceName, "success", map[string]any{"action": action, "bind_address": data.MySQLBindAddress})
	case "run_query":
		result, err := a.databases.ExecuteAdminQuery(data.MySQLAdminQuery, 250)
		if err != nil {
			data.RequestError = mysqlServiceErrorMessage(err)
			a.recordAudit(r.Context(), "mysql.admin_query", status.ServiceName, "failure", map[string]any{"error": err.Error(), "query": auditQueryPreview(data.MySQLAdminQuery)})
			break
		}
		data.MySQLAdminQueryResult = result
		data.SuccessMessage = firstNonEmpty(result.Message, "MySQL query executed successfully.")
		a.recordAudit(r.Context(), "mysql.admin_query", status.ServiceName, "success", map[string]any{"query": auditQueryPreview(data.MySQLAdminQuery), "rows": result.RowCount, "truncated": result.Truncated})
	default:
		data.RequestError = "Invalid MySQL action."
	}

	refreshData()

	a.render(r.Context(), w, r.URL.Path, "mysql_service.html", data)
}

func (a *App) mysqlServiceTemplateData(r *http.Request, status system.MySQLServiceStatus, entries []system.DatabaseAccess) TemplateData {
	data := TemplateData{
		Title:              "MySQL",
		DatabaseStatus:     a.databaseStatus(r.Context()),
		Metrics:            a.metrics.Snapshot(),
		DatabaseAccess:     entries,
		MySQLServiceStatus: status,
		OpenAIConfigured:   a.openAIConfigured(),
		OpenAIModel:        firstNonEmpty(strings.TrimSpace(a.cfg.OpenAIModel), "gpt-4.1-mini"),
	}
	data.MySQLMaxConnections = defaultMySQLServiceField(status.MaxConnections, "151")
	data.MySQLMaxUserConnections = strconv.Itoa(status.MaxUserConnections)
	data.MySQLWaitTimeout = defaultMySQLServiceField(status.WaitTimeout, "28800")
	data.MySQLInteractiveTimeout = defaultMySQLServiceField(status.InteractiveTimeout, "28800")
	data.MySQLMaxConnectErrors = defaultMySQLServiceField(status.MaxConnectErrors, "100")
	data.MySQLThreadCacheSize = defaultMySQLServiceField(status.ThreadCacheSize, "9")
	data.MySQLTableOpenCache = defaultMySQLServiceField(status.TableOpenCache, "2000")
	data.MySQLPort = defaultMySQLServiceField(status.Port, "3306")
	data.MySQLBindAddress = firstNonEmpty(status.BindAddress, "127.0.0.1")
	data.MySQLRemoteAccessEnabled = data.MySQLBindAddress != "127.0.0.1" && data.MySQLBindAddress != "localhost"
	data.MySQLSlowQueryLogEnabled = status.SlowQueryLogEnabled
	data.MySQLSlowQueryLogFile = firstNonEmpty(status.SlowQueryLogFile, "/var/log/mysql/slow-query.log")
	data.MySQLLongQueryTime = firstNonEmpty(status.LongQueryTimeSeconds, "2")
	data.MySQLLogLines = "200"
	bufferPoolMB := status.InnodbBufferPoolSizeBytes / (1024 * 1024)
	if bufferPoolMB <= 0 {
		data.MySQLInnodbBufferPoolSizeMB = "128"
	} else {
		data.MySQLInnodbBufferPoolSizeMB = strconv.FormatInt(bufferPoolMB, 10)
	}
	return data
}

func defaultMySQLServiceField(value int, fallback string) string {
	if value <= 0 {
		return fallback
	}
	return strconv.Itoa(value)
}

func mysqlServiceConfigSpecFromForm(data TemplateData) (system.MySQLServiceConfigSpec, error) {
	maxConnections, err := strconv.Atoi(strings.TrimSpace(data.MySQLMaxConnections))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("Max connections must be a valid number.")
	}
	maxUserConnections, err := strconv.Atoi(strings.TrimSpace(data.MySQLMaxUserConnections))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("Max user connections must be a valid number.")
	}
	waitTimeout, err := strconv.Atoi(strings.TrimSpace(data.MySQLWaitTimeout))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("Wait timeout must be a valid number.")
	}
	interactiveTimeout, err := strconv.Atoi(strings.TrimSpace(data.MySQLInteractiveTimeout))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("Interactive timeout must be a valid number.")
	}
	maxConnectErrors, err := strconv.Atoi(strings.TrimSpace(data.MySQLMaxConnectErrors))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("Max connect errors must be a valid number.")
	}
	threadCacheSize, err := strconv.Atoi(strings.TrimSpace(data.MySQLThreadCacheSize))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("Thread cache size must be a valid number.")
	}
	tableOpenCache, err := strconv.Atoi(strings.TrimSpace(data.MySQLTableOpenCache))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("Table open cache must be a valid number.")
	}
	port, err := strconv.Atoi(strings.TrimSpace(data.MySQLPort))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("MySQL port must be a valid number.")
	}
	innodbBufferPoolSizeMB, err := strconv.Atoi(strings.TrimSpace(data.MySQLInnodbBufferPoolSizeMB))
	if err != nil {
		return system.MySQLServiceConfigSpec{}, errors.New("InnoDB buffer pool size must be a valid number in MB.")
	}
	return system.MySQLServiceConfigSpec{
		MaxConnections:         maxConnections,
		MaxUserConnections:     maxUserConnections,
		WaitTimeout:            waitTimeout,
		InteractiveTimeout:     interactiveTimeout,
		MaxConnectErrors:       maxConnectErrors,
		ThreadCacheSize:        threadCacheSize,
		TableOpenCache:         tableOpenCache,
		InnodbBufferPoolSizeMB: innodbBufferPoolSizeMB,
		Port:                   port,
		BindAddress:            strings.TrimSpace(data.MySQLBindAddress),
		SlowQueryLogEnabled:    data.MySQLSlowQueryLogEnabled,
		SlowQueryLogFile:       strings.TrimSpace(data.MySQLSlowQueryLogFile),
		LongQueryTimeSeconds:   strings.TrimSpace(data.MySQLLongQueryTime),
	}, nil
}

func mysqlServiceErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	switch {
	case errors.Is(err, system.ErrInvalidMySQLMaxConnections):
		message = "Max connections must be greater than zero."
	case errors.Is(err, system.ErrInvalidMySQLMaxUserConnections):
		message = "Max user connections must be zero or a positive number."
	case errors.Is(err, system.ErrInvalidMySQLWaitTimeout):
		message = "Wait timeout must be greater than zero."
	case errors.Is(err, system.ErrInvalidMySQLInteractiveTimeout):
		message = "Interactive timeout must be greater than zero."
	case errors.Is(err, system.ErrInvalidMySQLMaxConnectErrors):
		message = "Max connect errors must be greater than zero."
	case errors.Is(err, system.ErrInvalidMySQLThreadCacheSize):
		message = "Thread cache size must be zero or a positive number."
	case errors.Is(err, system.ErrInvalidMySQLTableOpenCache):
		message = "Table open cache must be greater than zero."
	case errors.Is(err, system.ErrInvalidMySQLBufferPoolSize):
		message = "InnoDB buffer pool size must be greater than zero MB."
	case errors.Is(err, system.ErrInvalidMySQLBindAddress):
		message = "Bind address is not valid. Use values like 127.0.0.1, 0.0.0.0, ::, or localhost."
	case errors.Is(err, system.ErrInvalidMySQLPort):
		message = "MySQL port must be between 1 and 65535."
	case errors.Is(err, system.ErrInvalidMySQLLongQueryTime):
		message = "Long query time must be a valid number such as 1, 2, or 0.5."
	case errors.Is(err, system.ErrInvalidMySQLSlowQueryLogPath):
		message = "Slow query log path must be an absolute file path."
	case errors.Is(err, system.ErrInvalidMySQLLogLines):
		message = "Log line count must be between 1 and 2000."
	case errors.Is(err, system.ErrInvalidDatabaseQuery):
		message = "MySQL query cannot be empty."
	}
	return message
}

func (a *App) handleMySQLLogs(w http.ResponseWriter, r *http.Request) {
	status, inspectErr := a.databases.InspectService()
	data := TemplateData{
		Title:              "MySQL logs",
		DatabaseStatus:     a.databaseStatus(r.Context()),
		Metrics:            a.metrics.Snapshot(),
		MySQLServiceStatus: status,
		MySQLLogLines:      "200",
	}
	if inspectErr != nil {
		data.RequestError = "MySQL service status could not be loaded: " + mysqlServiceErrorMessage(inspectErr)
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.RequestError = "The submitted MySQL logs form could not be parsed."
			a.render(r.Context(), w, r.URL.Path, "mysql_logs.html", data)
			return
		}
		if lines := strings.TrimSpace(r.FormValue("mysql_log_lines")); lines != "" {
			data.MySQLLogLines = lines
		}
	}
	lines, err := strconv.Atoi(strings.TrimSpace(data.MySQLLogLines))
	if err != nil || lines <= 0 {
		lines = 200
		data.MySQLLogLines = "200"
	}
	output, logsErr := a.databases.ServiceLogs(lines)
	data.CommandOutput = output
	if logsErr != nil {
		data.RequestError = "MySQL logs could not be loaded: " + mysqlServiceErrorMessage(logsErr)
	} else {
		data.SuccessMessage = "MySQL logs loaded successfully."
	}
	if refreshedStatus, err := a.databases.InspectService(); err == nil {
		data.MySQLServiceStatus = refreshedStatus
	}
	data.MySQLSlowQueryLogEnabled = data.MySQLServiceStatus.SlowQueryLogEnabled
	data.MySQLSlowQueryLogFile = data.MySQLServiceStatus.SlowQueryLogFile
	a.render(r.Context(), w, r.URL.Path, "mysql_logs.html", data)
}

func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	users := a.listLinuxUsers()
	sites := []domain.ManagedSite(nil)
	var sitesErr error
	if a.store != nil {
		sites, sitesErr = a.store.ListManagedSites(r.Context())
		if sitesErr != nil && a.logger != nil {
			a.logger.Error("list managed sites", "error", sitesErr)
		}
	}
	versions := a.listPHPVersions()

	usedPorts := []store.UsedPort(nil)
	if a.store != nil {
		usedPorts, _ = a.store.ListUsedPorts(r.Context())
	}

	if r.Method == http.MethodGet {
		requestError := ""
		if sitesErr != nil {
			requestError = "Managed site list could not be loaded: " + sitesErr.Error()
		}
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     users,
			ManagedSites:   sites,
			PHPVersions:    versions,
			UsedPorts:      usedPorts,
			RequestError:   requestError,
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

	if spec.Mode == "reverse_proxy" && spec.UpstreamURL != "" {
		if port := extractPortFromUpstream(spec.UpstreamURL); port != "" {
			for _, up := range usedPorts {
				if up.Port == port {
					a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
						Title:          "Sites",
						DatabaseStatus: a.databaseStatus(r.Context()),
						Metrics:        a.metrics.Snapshot(),
						LinuxUsers:     users,
						ManagedSites:   sites,
						PHPVersions:    versions,
						UsedPorts:      usedPorts,
						RequestError:   fmt.Sprintf("Port %s is already used by %q.", port, up.Owner),
					})
					return
				}
			}
		}
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
		if err := a.store.CreateManagedSite(r.Context(), domain.ManagedSite{
			Name:            spec.Name,
			OwnerLinuxUser:  spec.OwnerLinuxUser,
			DomainName:      spec.Domain,
			RootDirectory:   spec.RootDirectory,
			Runtime:         spec.Mode,
			UpstreamURL:     spec.UpstreamURL,
			PHPVersion:      spec.PHPVersion,
			NginxConfigPath: configPath,
		}); err != nil {
			a.recordAudit(r.Context(), "nginx.apply_site", spec.Name, "failure", map[string]any{"domain": spec.Domain, "mode": spec.Mode, "config_path": configPath, "store_error": err.Error()})
			a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
				Title:          "Sites",
				DatabaseStatus: a.databaseStatus(r.Context()),
				Metrics:        a.metrics.Snapshot(),
				LinuxUsers:     users,
				ManagedSites:   sites,
				PHPVersions:    versions,
				RequestError:   "Site Nginx config was applied successfully, but the panel could not save the site record: " + err.Error(),
				ResultPath:     configPath,
			})
			return
		}
	}

	a.recordAudit(r.Context(), "nginx.apply_site", spec.Name, "success", map[string]any{"domain": spec.Domain, "mode": spec.Mode, "config_path": configPath})
	sites = a.listManagedSites(r)
	if a.store != nil {
		usedPorts, _ = a.store.ListUsedPorts(r.Context())
	}
	a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
		Title:          "Sites",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		LinuxUsers:     users,
		ManagedSites:   sites,
		PHPVersions:    versions,
		UsedPorts:      usedPorts,
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
	primaryDomain := strings.TrimSpace(r.FormValue("tls_domain"))
	request := system.TLSRequest{
		Domain:            primaryDomain,
		AdditionalDomains: parseAdditionalDomains(r.FormValue("tls_additional_domains")),
		Email:             r.FormValue("tls_email"),
		Redirect:          r.FormValue("tls_redirect") == "1",
		ConfigPath:        siteConfigPathForDomain(sites, primaryDomain),
	}

	output, err := a.nginx.EnableTLS(request)
	if err != nil {
		a.recordAudit(r.Context(), "nginx.enable_tls", request.Domain, "failure", map[string]any{"email": request.Email, "additional_domains": request.AdditionalDomains, "error": err.Error()})
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

	a.recordAudit(r.Context(), "nginx.enable_tls", request.Domain, "success", map[string]any{"email": request.Email, "redirect": request.Redirect, "additional_domains": request.AdditionalDomains})
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
	repositoryURL := repositoryStatus.RemoteURL
	gitAuthStatus, gitAuthErr := a.gitAuth.Inspect(system.GitAuthInspectSpec{User: site.OwnerLinuxUser, SiteName: site.Name, RepositoryURL: repositoryURL})
	releases := a.listSiteDeploymentReleases(r, site.RootDirectory, site.OwnerLinuxUser)

	if r.Method == http.MethodGet {
		data := TemplateData{
			SiteDetailTab:        firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tab")), "overview"),
			CronFilter:           firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("cron_filter")), "site"),
			CronEditID:           strings.TrimSpace(r.URL.Query().Get("cron_edit")),
			CronLogID:            strings.TrimSpace(r.URL.Query().Get("cron_log")),
			DNSRecordEditOldName: strings.TrimSpace(r.URL.Query().Get("dns_edit_name")),
			DNSRecordEditOldType: strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("dns_edit_type"))),
		}
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
		SiteDetailTab:                  siteDetailTabForAction(action),
		GitRepositoryURL:               firstNonEmpty(strings.TrimSpace(r.FormValue("repository_url")), repositoryURL),
		GitBranch:                      firstNonEmpty(strings.TrimSpace(r.FormValue("branch")), branch),
		GitPostDeployCommand:           r.FormValue("post_deploy_command"),
		GitCustomCommand:               r.FormValue("git_custom_command"),
		SSHWorkingDirectory:            firstNonEmpty(strings.TrimSpace(r.FormValue("ssh_working_directory")), site.RootDirectory),
		SSHCommandBody:                 r.FormValue("ssh_command_body"),
		SSHPublicKeyInput:              r.FormValue("ssh_public_key"),
		SSHPasswordInput:               r.FormValue("ssh_password"),
		SSHRemoveKeyFingerprint:        strings.TrimSpace(r.FormValue("ssh_remove_fingerprint")),
		DNSSelectedZoneID:              strings.TrimSpace(r.FormValue("dns_zone_id")),
		DNSSelectedZoneName:            strings.TrimSpace(r.FormValue("dns_zone_name")),
		DNSRecordName:                  strings.TrimSpace(r.FormValue("dns_record_name")),
		DNSRecordType:                  strings.ToUpper(strings.TrimSpace(r.FormValue("dns_record_type"))),
		DNSRecordTTL:                   strings.TrimSpace(r.FormValue("dns_record_ttl")),
		DNSRecordValues:                r.FormValue("dns_record_values"),
		DNSRecordEditOldName:           strings.TrimSpace(r.FormValue("dns_record_old_name")),
		DNSRecordEditOldType:           strings.ToUpper(strings.TrimSpace(r.FormValue("dns_record_old_type"))),
		BackupS3Bucket:                 strings.TrimSpace(r.FormValue("backup_s3_bucket")),
		BackupS3Region:                 strings.TrimSpace(r.FormValue("backup_s3_region")),
		BackupS3Prefix:                 strings.TrimSpace(r.FormValue("backup_s3_prefix")),
		AutoDeployEnabled:              r.FormValue("auto_deploy_enabled") == "1",
		AutoDeployBranch:               strings.TrimSpace(r.FormValue("auto_deploy_branch")),
		AutoDeploySecret:               strings.TrimSpace(r.FormValue("auto_deploy_secret")),
		AutoDeployCommand:              r.FormValue("auto_deploy_command"),
		AutoDeployNodeVersion:          strings.TrimSpace(r.FormValue("auto_deploy_node_version")),
		AutoDeployNotifyEmail:          strings.TrimSpace(r.FormValue("auto_deploy_notify_email")),
		RuntimeNodeVersion:             strings.TrimSpace(r.FormValue("node_version")),
		PreferredNodeVersion:           strings.TrimSpace(r.FormValue("preferred_node_version")),
		PM2NodeVersion:                 strings.TrimSpace(r.FormValue("pm2_node_version")),
		PM2ProcessName:                 firstNonEmpty(strings.TrimSpace(r.FormValue("process_name")), site.Name),
		PM2ScriptPath:                  strings.TrimSpace(r.FormValue("script_path")),
		PM2Arguments:                   strings.TrimSpace(r.FormValue("process_arguments")),
		SubdomainLabel:                 strings.TrimSpace(r.FormValue("subdomain_label")),
		SubdomainMode:                  firstNonEmpty(strings.TrimSpace(r.FormValue("subdomain_mode")), "reverse_proxy"),
		SubdomainDirectoryName:         strings.TrimSpace(r.FormValue("subdomain_directory_name")),
		SubdomainUpstreamURL:           strings.TrimSpace(r.FormValue("subdomain_upstream_url")),
		SubdomainPHPVersion:            strings.TrimSpace(r.FormValue("subdomain_php_version")),
		SubdomainRootDirectory:         strings.TrimSpace(r.FormValue("subdomain_root_directory")),
		SubdomainRepositoryURL:         strings.TrimSpace(r.FormValue("subdomain_repository_url")),
		SubdomainBranch:                strings.TrimSpace(r.FormValue("subdomain_branch")),
		SubdomainPostDeployCommand:     r.FormValue("subdomain_post_deploy_command"),
		SubdomainAutoDeployEnabled:     r.FormValue("subdomain_auto_deploy_enabled") == "1",
		SubdomainAutoDeployBranch:      strings.TrimSpace(r.FormValue("subdomain_auto_deploy_branch")),
		SubdomainAutoDeploySecret:      strings.TrimSpace(r.FormValue("subdomain_auto_deploy_secret")),
		SubdomainAutoDeployCommand:     r.FormValue("subdomain_auto_deploy_command"),
		SubdomainAutoDeployNodeVersion: strings.TrimSpace(r.FormValue("subdomain_auto_deploy_node_version")),
		SubdomainAutoDeployNotifyEmail: strings.TrimSpace(r.FormValue("subdomain_auto_deploy_notify_email")),
		SubdomainTLSEmail:              strings.TrimSpace(r.FormValue("subdomain_tls_email")),
		RuntimeCommandName:             strings.TrimSpace(r.FormValue("runtime_command_name")),
		RuntimeCommandNodeVersion:      strings.TrimSpace(r.FormValue("runtime_command_node_version")),
		RuntimeCommandBody:             r.FormValue("runtime_command_body"),
		CronSchedule:                   strings.TrimSpace(r.FormValue("cron_schedule")),
		CronCommand:                    strings.TrimSpace(r.FormValue("cron_command")),
		CronRunInSiteRoot:              r.FormValue("cron_run_in_site_root") != "0",
		CronFilter:                     firstNonEmpty(strings.TrimSpace(r.FormValue("cron_filter")), "site"),
		CronEditID:                     strings.TrimSpace(r.FormValue("cron_id")),
		CronLogID:                      strings.TrimSpace(r.FormValue("cron_log_id")),
		GitCredentialHost:              firstNonEmpty(strings.TrimSpace(r.FormValue("credential_host")), gitAuthStatus.RepositoryHost),
		LaravelExtraWritablePaths:      r.FormValue("laravel_extra_writable_paths"),
		NginxConfigContent:             r.FormValue("nginx_config_content"),
	}
	if commandID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("runtime_command_id")), 10, 64); err == nil {
		data.RuntimeCommandID = commandID
	}
	if subdomainDeleteID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("subdomain_id")), 10, 64); err == nil {
		data.SubdomainDeleteID = subdomainDeleteID
	}
	nginxTargetType := firstNonEmpty(strings.TrimSpace(r.FormValue("nginx_target_type")), "site")
	var nginxTargetID int64
	if targetID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("nginx_target_id")), 10, 64); err == nil {
		nginxTargetID = targetID
	}
	var nginxRevisionID int64
	if revisionID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("nginx_revision_id")), 10, 64); err == nil {
		nginxRevisionID = revisionID
	}

	var output string
	var actionErr error
	var successMessage string
	subdomainsForConfig, _ := a.store.ListSiteSubdomains(r.Context(), site.ID)

	switch action {
	case "sync_repository":
		if data.GitRepositoryURL == "" {
			data.RequestError = "Repository URL is required."
			break
		}
		spec := system.DeploySpec{
			RepositoryURL:         data.GitRepositoryURL,
			Branch:                data.GitBranch,
			TargetDirectory:       site.RootDirectory,
			RunAsUser:             site.OwnerLinuxUser,
			GitSiteName:           site.Name,
			PostDeployCommand:     data.GitPostDeployCommand,
			PostDeployNodeVersion: strings.TrimSpace(data.PreferredNodeVersion),
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
		output, actionErr = a.runtime.InstallPM2(system.PM2InstallSpec{User: site.OwnerLinuxUser, NodeVersion: firstNonEmpty(data.PM2NodeVersion, data.PreferredNodeVersion)})
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
		output, actionErr = a.runtime.StartPM2(system.PM2StartSpec{User: site.OwnerLinuxUser, WorkingDirectory: site.RootDirectory, ProcessName: data.PM2ProcessName, ScriptPath: data.PM2ScriptPath, Arguments: data.PM2Arguments, NodeVersion: firstNonEmpty(data.PM2NodeVersion, data.PreferredNodeVersion)})
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
	case "run_npm_script":
		scriptName := strings.TrimSpace(r.FormValue("script_name"))
		nodeVersion := firstNonEmpty(strings.TrimSpace(r.FormValue("npm_script_node_version")), data.PreferredNodeVersion)
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
			Domain:            strings.TrimSpace(r.FormValue("tls_domain")),
			AdditionalDomains: parseAdditionalDomains(r.FormValue("tls_additional_domains")),
			Email:             strings.TrimSpace(r.FormValue("tls_email")),
			Redirect:          r.FormValue("tls_redirect") == "1",
			ConfigPath:        strings.TrimSpace(site.NginxConfigPath),
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
			a.recordAudit(r.Context(), "nginx.enable_tls", tlsRequest.Domain, "failure", map[string]any{"email": tlsRequest.Email, "additional_domains": tlsRequest.AdditionalDomains, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "nginx.enable_tls", tlsRequest.Domain, "success", map[string]any{"email": tlsRequest.Email, "redirect": tlsRequest.Redirect, "additional_domains": tlsRequest.AdditionalDomains})
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
		nodeVersion := firstNonEmpty(strings.TrimSpace(r.FormValue("npm_script_node_version")), data.PreferredNodeVersion)
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
			data.RuntimeCommandNodeVersion = data.PreferredNodeVersion
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
		data.RuntimeCommandNodeVersion = data.PreferredNodeVersion
		data.RuntimeCommandBody = ""
		successMessage = "Runtime command profile deleted."
	case "save_node_version":
		if !validNodeVersionSelection(data.PreferredNodeVersion) {
			data.RequestError = "Node version is invalid. Use installed versions, exact semver, or aliases like lts/* or node."
			break
		}
		if err := a.store.UpdateManagedSiteNodeVersion(r.Context(), site.Name, strings.TrimSpace(data.PreferredNodeVersion)); err != nil {
			data.RequestError = "Could not save site node version: " + err.Error()
			break
		}
		site.NodeVersion = strings.TrimSpace(data.PreferredNodeVersion)
		a.recordAudit(r.Context(), "site.node_version.save", site.Name, "success", map[string]any{"node_version": site.NodeVersion})
		successMessage = "Site node version saved."
	case "save_auto_deploy":
		if data.AutoDeployBranch == "" {
			data.AutoDeployBranch = strings.TrimSpace(branch)
		}
		if data.AutoDeployEnabled && data.AutoDeploySecret == "" {
			secret, err := randomPassword(32)
			if err != nil {
				data.RequestError = "Could not generate auto deploy secret."
				break
			}
			data.AutoDeploySecret = secret
		}
		if err := a.store.UpdateManagedSiteAutoDeploy(r.Context(), site.Name, data.AutoDeployEnabled, data.AutoDeployBranch, data.AutoDeploySecret, data.AutoDeployCommand, data.AutoDeployNodeVersion, data.AutoDeployNotifyEmail); err != nil {
			data.RequestError = "Could not save auto deploy settings: " + err.Error()
			break
		}
		site.AutoDeployEnabled = data.AutoDeployEnabled
		site.AutoDeployBranch = data.AutoDeployBranch
		site.AutoDeploySecret = data.AutoDeploySecret
		site.AutoDeployCommand = data.AutoDeployCommand
		site.AutoDeployNodeVersion = data.AutoDeployNodeVersion
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
			data.AutoDeployBranch = firstNonEmpty(site.AutoDeployBranch, branch)
		}
		if err := a.store.UpdateManagedSiteAutoDeploy(r.Context(), site.Name, data.AutoDeployEnabled || site.AutoDeployEnabled, data.AutoDeployBranch, data.AutoDeploySecret, firstNonEmpty(data.AutoDeployCommand, site.AutoDeployCommand), firstNonEmpty(data.AutoDeployNodeVersion, site.AutoDeployNodeVersion), firstNonEmpty(data.AutoDeployNotifyEmail, site.AutoDeployNotifyEmail)); err != nil {
			data.RequestError = "Could not rotate auto deploy secret: " + err.Error()
			break
		}
		site.AutoDeploySecret = data.AutoDeploySecret
		site.AutoDeployNodeVersion = firstNonEmpty(data.AutoDeployNodeVersion, site.AutoDeployNodeVersion)
		site.AutoDeployNotifyEmail = firstNonEmpty(data.AutoDeployNotifyEmail, site.AutoDeployNotifyEmail)
		a.recordAudit(r.Context(), "site.auto_deploy.rotate_secret", site.Name, "success", nil)
		successMessage = "Auto deploy secret rotated."
	case "add_subdomain":
		if data.SubdomainAutoDeployEnabled && data.SubdomainAutoDeploySecret == "" {
			secret, err := randomPassword(32)
			if err != nil {
				data.RequestError = "Could not generate subdomain auto deploy secret."
				break
			}
			data.SubdomainAutoDeploySecret = secret
		}
		if data.SubdomainMode == "reverse_proxy" && data.SubdomainUpstreamURL != "" && a.store != nil {
			if port := extractPortFromUpstream(data.SubdomainUpstreamURL); port != "" {
				if ups, _ := a.store.ListUsedPorts(r.Context()); ups != nil {
					for _, up := range ups {
						if up.Port == port {
							data.RequestError = fmt.Sprintf("Port %s is already used by %q.", port, up.Owner)
							break
						}
					}
				}
			}
		}
		if data.RequestError != "" {
			break
		}
		subdomainRecord, siteSpec, err := buildSiteSubdomain(site, a.cfg.SubdomainRootBaseDir, data.SubdomainLabel, data.SubdomainMode, data.SubdomainUpstreamURL, data.SubdomainPHPVersion, data.SubdomainDirectoryName)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		subdomainRecord.RepositoryURL = data.SubdomainRepositoryURL
		subdomainRecord.BranchName = firstNonEmpty(data.SubdomainBranch, branch)
		subdomainRecord.PostDeployCommand = data.SubdomainPostDeployCommand
		subdomainRecord.AutoDeployEnabled = data.SubdomainAutoDeployEnabled
		subdomainRecord.AutoDeployBranch = firstNonEmpty(data.SubdomainAutoDeployBranch, subdomainRecord.BranchName)
		subdomainRecord.AutoDeploySecret = data.SubdomainAutoDeploySecret
		subdomainRecord.AutoDeployCommand = data.SubdomainAutoDeployCommand
		subdomainRecord.AutoDeployNodeVersion = data.SubdomainAutoDeployNodeVersion
		subdomainRecord.AutoDeployNotifyEmail = data.SubdomainAutoDeployNotifyEmail
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
		data.SubdomainDirectoryName = ""
		data.SubdomainUpstreamURL = ""
		data.SubdomainPHPVersion = ""
		data.SubdomainRepositoryURL = ""
		data.SubdomainBranch = ""
		data.SubdomainPostDeployCommand = ""
		data.SubdomainAutoDeployEnabled = false
		data.SubdomainAutoDeployBranch = ""
		data.SubdomainAutoDeploySecret = ""
		data.SubdomainAutoDeployCommand = ""
		data.SubdomainAutoDeployNodeVersion = ""
		data.SubdomainAutoDeployNotifyEmail = ""
	case "save_subdomain_deploy":
		subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if err != nil {
			data.RequestError = "Could not load subdomains."
			break
		}
		subdomain, ok := findSiteSubdomain(subdomains, data.SubdomainDeleteID)
		if !ok {
			data.RequestError = "Subdomain could not be found."
			break
		}
		if data.SubdomainAutoDeployEnabled && data.SubdomainAutoDeploySecret == "" {
			secret, err := randomPassword(32)
			if err != nil {
				data.RequestError = "Could not generate subdomain auto deploy secret."
				break
			}
			data.SubdomainAutoDeploySecret = secret
		}
		if err := a.store.UpdateSiteSubdomainDeploy(r.Context(), site.ID, subdomain.ID, data.SubdomainRepositoryURL, firstNonEmpty(data.SubdomainBranch, subdomain.BranchName, branch), data.SubdomainPostDeployCommand, data.SubdomainAutoDeployEnabled, firstNonEmpty(data.SubdomainAutoDeployBranch, data.SubdomainBranch, subdomain.AutoDeployBranch, subdomain.BranchName, branch), data.SubdomainAutoDeploySecret, data.SubdomainAutoDeployCommand, data.SubdomainAutoDeployNodeVersion, data.SubdomainAutoDeployNotifyEmail); err != nil {
			data.RequestError = "Could not save subdomain deploy settings: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.deploy.save", subdomain.FullDomain, "success", map[string]any{"enabled": data.SubdomainAutoDeployEnabled, "branch": firstNonEmpty(data.SubdomainAutoDeployBranch, data.SubdomainBranch, subdomain.AutoDeployBranch, subdomain.BranchName, branch)})
		successMessage = "Subdomain deploy settings saved."
	case "rotate_subdomain_auto_deploy_secret":
		subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if err != nil {
			data.RequestError = "Could not load subdomains."
			break
		}
		subdomain, ok := findSiteSubdomain(subdomains, data.SubdomainDeleteID)
		if !ok {
			data.RequestError = "Subdomain could not be found."
			break
		}
		secret, err := randomPassword(32)
		if err != nil {
			data.RequestError = "Could not rotate subdomain auto deploy secret."
			break
		}
		data.SubdomainAutoDeploySecret = secret
		if err := a.store.UpdateSiteSubdomainDeploy(r.Context(), site.ID, subdomain.ID, firstNonEmpty(data.SubdomainRepositoryURL, subdomain.RepositoryURL), firstNonEmpty(data.SubdomainBranch, subdomain.BranchName, branch), firstNonEmpty(data.SubdomainPostDeployCommand, subdomain.PostDeployCommand), data.SubdomainAutoDeployEnabled || subdomain.AutoDeployEnabled, firstNonEmpty(data.SubdomainAutoDeployBranch, subdomain.AutoDeployBranch, subdomain.BranchName, branch), secret, firstNonEmpty(data.SubdomainAutoDeployCommand, subdomain.AutoDeployCommand), firstNonEmpty(data.SubdomainAutoDeployNodeVersion, subdomain.AutoDeployNodeVersion), firstNonEmpty(data.SubdomainAutoDeployNotifyEmail, subdomain.AutoDeployNotifyEmail)); err != nil {
			data.RequestError = "Could not rotate subdomain auto deploy secret: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.deploy.rotate_secret", subdomain.FullDomain, "success", nil)
		successMessage = "Subdomain auto deploy secret rotated."
	case "move_subdomain_root_preview":
		subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if err != nil {
			data.RequestError = "Could not load subdomains."
			break
		}
		subdomain, ok := findSiteSubdomain(subdomains, data.SubdomainDeleteID)
		if !ok {
			data.RequestError = "Subdomain could not be found."
			break
		}
		preview := a.inspectSubdomainMovePreview(r.Context(), site, subdomain, firstNonEmpty(data.SubdomainDirectoryName, subdomain.Subdomain))
		data.PreviewSubdomainID = subdomain.ID
		data.SubdomainMovePreviewFrom = preview.From
		data.SubdomainMovePreviewTo = preview.To
		data.SubdomainMovePreviewTargetExists = preview.TargetExists
		data.SubdomainMovePreviewTargetEmpty = preview.TargetEmpty
		data.SubdomainMovePreviewTargetGitRepo = preview.TargetGitRepo
		data.SubdomainMovePreviewTargetState = preview.TargetState
		successMessage = "Move preview updated."
	case "move_subdomain_root":
		subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if err != nil {
			data.RequestError = "Could not load subdomains."
			break
		}
		subdomain, ok := findSiteSubdomain(subdomains, data.SubdomainDeleteID)
		if !ok {
			data.RequestError = "Subdomain could not be found."
			break
		}
		newRoot := buildManagedSubdomainRootDirectory(site, a.cfg.SubdomainRootBaseDir, firstNonEmpty(data.SubdomainDirectoryName, subdomain.Subdomain))
		if filepath.Clean(newRoot) == filepath.Clean(subdomain.RootDirectory) {
			data.RequestError = "Subdomain root is already set to that directory."
			break
		}
		moveScript := "set -e; mkdir -p $(dirname " + shellSingleQuote(newRoot) + "); if [ -e " + shellSingleQuote(newRoot) + " ]; then echo 'Destination already exists'; exit 1; fi; if [ -e " + shellSingleQuote(subdomain.RootDirectory) + " ]; then mv " + shellSingleQuote(subdomain.RootDirectory) + " " + shellSingleQuote(newRoot) + "; else mkdir -p " + shellSingleQuote(newRoot) + "; fi"
		output, actionErr := a.helper.Call(r.Context(), "runtime.run_shell_command", system.ShellCommandSpec{User: site.OwnerLinuxUser, WorkingDirectory: filepath.Dir(subdomain.RootDirectory), CommandBody: moveScript}, nil)
		if actionErr != nil {
			data.RequestError = "Could not move subdomain root: " + actionErr.Error()
			data.CommandOutput = output
			a.recordAudit(r.Context(), "site.subdomain.root.move", subdomain.FullDomain, "failure", map[string]any{"from": subdomain.RootDirectory, "to": newRoot, "error": actionErr.Error()})
			break
		}
		siteSpec := buildSubdomainSiteSpec(site, subdomain, newRoot)
		configPath, actionErr := a.nginx.ApplySite(siteSpec)
		if actionErr != nil {
			data.RequestError = "Subdomain files moved but Nginx config could not be updated: " + actionErr.Error()
			data.CommandOutput = output
			break
		}
		if err := a.store.UpdateSiteSubdomainLocation(r.Context(), site.ID, subdomain.ID, newRoot, configPath); err != nil {
			data.RequestError = "Subdomain root moved but store update failed: " + err.Error()
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.subdomain.root.move", subdomain.FullDomain, "success", map[string]any{"from": subdomain.RootDirectory, "to": newRoot})
		successMessage = "Subdomain root directory moved successfully."
	case "rollback_subdomain_release":
		subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if err != nil {
			data.RequestError = "Could not load subdomains."
			break
		}
		subdomain, ok := findSiteSubdomain(subdomains, data.SubdomainDeleteID)
		if !ok {
			data.RequestError = "Subdomain could not be found."
			break
		}
		releaseCommit := strings.TrimSpace(r.FormValue("release_commit_sha"))
		if releaseCommit == "" {
			data.RequestError = "Release commit is required for rollback."
			break
		}
		result, actionErr := a.deploys.Rollback(system.RollbackSpec{TargetDirectory: subdomain.RootDirectory, RunAsUser: site.OwnerLinuxUser, ReleaseCommitSHA: releaseCommit, PostDeployCommand: firstNonEmpty(strings.TrimSpace(r.FormValue("rollback_post_deploy_command")), subdomain.PostDeployCommand), PostDeployNodeVersion: strings.TrimSpace(subdomain.NodeVersion)})
		if actionErr != nil {
			data.RequestError = actionErr.Error()
			data.CommandOutput = result.Output
			a.recordAudit(r.Context(), "deploy.subdomain_rollback", subdomain.FullDomain, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "commit_sha": releaseCommit, "error": actionErr.Error(), "subdomain_id": subdomain.ID})
			break
		}
		if a.store != nil {
			_ = a.store.CreateDeploymentRelease(r.Context(), domain.DeploymentRelease{RepositoryURL: subdomain.RepositoryURL, BranchName: "rollback", TargetDirectory: subdomain.RootDirectory, RunAsUser: site.OwnerLinuxUser, Action: result.Action, Status: "success", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output})
		}
		data.CommandOutput = result.Output
		a.recordAudit(r.Context(), "deploy.subdomain_rollback", subdomain.FullDomain, "success", map[string]any{"run_as_user": site.OwnerLinuxUser, "commit_sha": releaseCommit, "subdomain_id": subdomain.ID})
		successMessage = "Subdomain rollback completed successfully."
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
		subdomainExtraDomains := parseAdditionalDomains(r.FormValue("subdomain_tls_additional_domains"))
		output, actionErr = a.nginx.EnableTLS(system.TLSRequest{Domain: selected.FullDomain, AdditionalDomains: subdomainExtraDomains, Email: data.SubdomainTLSEmail, Redirect: r.FormValue("subdomain_tls_redirect") == "1", ConfigPath: strings.TrimSpace(selected.NginxConfigPath)})
		if actionErr != nil {
			data.RequestError = "Could not enable TLS for subdomain: " + actionErr.Error()
			data.CommandOutput = output
			a.recordAudit(r.Context(), "site.subdomain.enable_tls", selected.FullDomain, "failure", map[string]any{"email": data.SubdomainTLSEmail, "additional_domains": subdomainExtraDomains, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.subdomain.enable_tls", selected.FullDomain, "success", map[string]any{"email": data.SubdomainTLSEmail, "additional_domains": subdomainExtraDomains})
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
	case "save_laravel_extra_writable_paths":
		normalizedPaths, normalizedRaw, normalizeErr := normalizeLaravelExtraWritablePathsInput(data.LaravelExtraWritablePaths)
		if normalizeErr != nil {
			data.RequestError = normalizeErr.Error()
			break
		}
		if err := a.store.UpdateManagedSiteLaravelExtraWritablePaths(r.Context(), site.Name, normalizedRaw); err != nil {
			data.RequestError = "Could not save Laravel extra writable paths: " + err.Error()
			break
		}
		data.LaravelExtraWritablePaths = normalizedRaw
		site.LaravelExtraWritablePaths = normalizedRaw
		a.recordAudit(r.Context(), "site.laravel_paths.save", site.Name, "success", map[string]any{"paths": normalizedPaths})
		successMessage = "Laravel extra writable paths saved."
	case "create_cron_job":
		output, actionErr = a.helper.Call(r.Context(), "cron.create", system.CronJobSpec{
			User:             site.OwnerLinuxUser,
			Schedule:         data.CronSchedule,
			Command:          data.CronCommand,
			SiteName:         site.Name,
			WorkingDirectory: site.RootDirectory,
			RunInSiteRoot:    data.CronRunInSiteRoot,
		}, nil)
		if actionErr != nil {
			message := actionErr.Error()
			switch {
			case errors.Is(actionErr, system.ErrInvalidUsername):
				message = "Site owner Linux user is invalid for cron management."
			case errors.Is(actionErr, system.ErrInvalidCronSchedule):
				message = "Cron schedule must be a standard 5-field expression or a supported @shortcut."
			case errors.Is(actionErr, system.ErrInvalidCronCommand):
				message = "Cron command cannot be empty."
			case errors.Is(actionErr, system.ErrInvalidTargetDirectory):
				message = "Site root directory is invalid for run-in-site-root cron jobs."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "site.cron.create", site.Name, "failure", map[string]any{"user": site.OwnerLinuxUser, "schedule": data.CronSchedule, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.cron.create", site.Name, "success", map[string]any{"user": site.OwnerLinuxUser, "schedule": data.CronSchedule, "run_in_site_root": data.CronRunInSiteRoot})
		data.CronSchedule = ""
		data.CronCommand = ""
		data.CronRunInSiteRoot = true
		successMessage = "Cron job created for the site owner successfully."
	case "update_cron_job":
		if strings.TrimSpace(data.CronEditID) == "" {
			data.RequestError = "Select a panel-managed cron job for this site to edit."
			break
		}
		output, actionErr = a.helper.Call(r.Context(), "cron.update", system.CronJobUpdateSpec{
			User:             site.OwnerLinuxUser,
			ID:               data.CronEditID,
			Schedule:         data.CronSchedule,
			Command:          data.CronCommand,
			SiteName:         site.Name,
			WorkingDirectory: site.RootDirectory,
			RunInSiteRoot:    data.CronRunInSiteRoot,
		}, nil)
		if actionErr != nil {
			message := actionErr.Error()
			switch {
			case errors.Is(actionErr, system.ErrInvalidUsername):
				message = "Site owner Linux user is invalid for cron management."
			case errors.Is(actionErr, system.ErrInvalidCronSchedule):
				message = "Cron schedule must be a standard 5-field expression or a supported @shortcut."
			case errors.Is(actionErr, system.ErrInvalidCronCommand):
				message = "Cron command cannot be empty."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "site.cron.update", site.Name, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": data.CronEditID, "schedule": data.CronSchedule, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.cron.update", site.Name, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": data.CronEditID, "schedule": data.CronSchedule, "run_in_site_root": data.CronRunInSiteRoot})
		data.CronEditID = ""
		data.CronSchedule = ""
		data.CronCommand = ""
		data.CronRunInSiteRoot = true
		successMessage = "Cron job updated successfully."
	case "delete_cron_job":
		cronRawLine := strings.TrimSpace(r.FormValue("cron_raw_line"))
		cronID := strings.TrimSpace(r.FormValue("cron_id"))
		output, actionErr = a.helper.Call(r.Context(), "cron.delete", system.CronJobDeleteSpec{User: site.OwnerLinuxUser, ID: cronID, RawLine: cronRawLine}, nil)
		if actionErr != nil {
			data.RequestError = "Cron job could not be deleted: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.cron.delete", site.Name, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.cron.delete", site.Name, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID})
		successMessage = "Cron job deleted successfully."
	case "clear_cron_log":
		cronID := strings.TrimSpace(r.FormValue("cron_id"))
		data.CronLogID = cronID
		output, actionErr = a.helper.Call(r.Context(), "cron.clear_log", map[string]string{"user": site.OwnerLinuxUser, "id": cronID}, nil)
		if actionErr != nil {
			data.RequestError = "Cron log could not be cleared: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.cron.clear_log", site.Name, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		data.CronLogNotice = "Cron log was cleared."
		a.recordAudit(r.Context(), "site.cron.clear_log", site.Name, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID})
		successMessage = "Cron log cleared successfully."
	case "rotate_cron_log":
		cronID := strings.TrimSpace(r.FormValue("cron_id"))
		data.CronLogID = cronID
		output, actionErr = a.helper.Call(r.Context(), "cron.rotate_log", map[string]string{"user": site.OwnerLinuxUser, "id": cronID}, nil)
		if actionErr != nil {
			data.RequestError = "Cron log could not be rotated: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.cron.rotate_log", site.Name, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		data.CronLogNotice = "Cron log was rotated to: " + output
		a.recordAudit(r.Context(), "site.cron.rotate_log", site.Name, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "rotated_path": output})
		successMessage = "Cron log rotated successfully."
	case "save_nginx_config":
		configPath, targetLabel, _, subdomainID, err := resolveNginxConfigTarget(site, subdomainsForConfig, nginxTargetType, nginxTargetID)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		if !isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, configPath) {
			data.RequestError = "Stored Nginx config path is outside the allowed Nginx config directory."
			break
		}
		if err := a.saveNginxConfigContent(r.Context(), site, subdomainID, configPath, data.NginxConfigContent, true); err != nil {
			data.RequestError = err.Error()
			a.recordAudit(r.Context(), "site.nginx_config.save", targetLabel, "failure", map[string]any{"config_path": configPath, "target_type": nginxTargetType, "subdomain_id": subdomainID, "error": err.Error()})
			break
		}
		data.NginxConfigNotice = "Nginx config saved, validated, and reloaded successfully."
		a.recordAudit(r.Context(), "site.nginx_config.save", targetLabel, "success", map[string]any{"config_path": configPath, "target_type": nginxTargetType, "subdomain_id": subdomainID})
		successMessage = "Nginx config updated successfully."
	case "validate_nginx_config":
		configPath, targetLabel, _, subdomainID, err := resolveNginxConfigTarget(site, subdomainsForConfig, nginxTargetType, nginxTargetID)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		if !isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, configPath) {
			data.RequestError = "Stored Nginx config path is outside the allowed Nginx config directory."
			break
		}
		output, actionErr = a.helper.Call(r.Context(), "nginx.validate_config", map[string]string{"path": configPath, "content": data.NginxConfigContent}, nil)
		if actionErr != nil {
			data.RequestError = "Nginx config validation failed: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.nginx_config.validate", targetLabel, "failure", map[string]any{"config_path": configPath, "target_type": nginxTargetType, "subdomain_id": subdomainID, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		data.NginxConfigNotice = "Validation passed. No file was changed."
		a.recordAudit(r.Context(), "site.nginx_config.validate", targetLabel, "success", map[string]any{"config_path": configPath, "target_type": nginxTargetType, "subdomain_id": subdomainID})
		successMessage = "Nginx config validated successfully."
	case "rollback_nginx_config":
		configPath, targetLabel, _, subdomainID, err := resolveNginxConfigTarget(site, subdomainsForConfig, nginxTargetType, nginxTargetID)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		if nginxRevisionID <= 0 {
			data.RequestError = "Select a saved Nginx config revision to roll back."
			break
		}
		revision, err := a.store.GetNginxConfigRevision(r.Context(), nginxRevisionID, site.ID, subdomainID)
		if err != nil {
			data.RequestError = "Could not load Nginx config revision: " + err.Error()
			break
		}
		if revision.ConfigPath != configPath {
			data.RequestError = "Selected revision does not belong to this Nginx config target."
			break
		}
		data.NginxConfigContent = revision.Content
		if err := a.saveNginxConfigContent(r.Context(), site, subdomainID, configPath, revision.Content, true); err != nil {
			data.RequestError = err.Error()
			a.recordAudit(r.Context(), "site.nginx_config.rollback", targetLabel, "failure", map[string]any{"config_path": configPath, "revision_id": nginxRevisionID, "target_type": nginxTargetType, "subdomain_id": subdomainID, "error": err.Error()})
			break
		}
		data.NginxConfigNotice = "Selected Nginx config revision was restored successfully."
		a.recordAudit(r.Context(), "site.nginx_config.rollback", targetLabel, "success", map[string]any{"config_path": configPath, "revision_id": nginxRevisionID, "target_type": nginxTargetType, "subdomain_id": subdomainID})
		successMessage = "Nginx config rollback completed successfully."
	case "add_ssh_key":
		key := strings.TrimSpace(data.SSHPublicKeyInput)
		if key == "" {
			data.RequestError = "SSH public key cannot be empty."
			break
		}
		addErr := a.sshAccounts.AddKey(system.SSHAddKeySpec{Username: site.OwnerLinuxUser, PublicKey: key})
		if addErr != nil {
			message := addErr.Error()
			if errors.Is(addErr, system.ErrInvalidSSHPublicKey) {
				message = "Provided value is not a valid SSH public key. Expected a single line like 'ssh-ed25519 AAAA... user@host'."
			} else if errors.Is(addErr, system.ErrInvalidUsername) {
				message = "Site owner Linux user is invalid for SSH account management."
			} else if errors.Is(addErr, system.ErrUserNotFound) {
				message = "Site owner Linux user does not exist on this server yet."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "site.ssh_account.add_key", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "error": addErr.Error()})
			break
		}
		data.SSHPublicKeyInput = ""
		a.recordAudit(r.Context(), "site.ssh_account.add_key", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser})
		successMessage = "SSH public key added to " + site.OwnerLinuxUser + "'s authorized_keys."
	case "remove_ssh_key":
		fingerprint := strings.TrimSpace(data.SSHRemoveKeyFingerprint)
		if fingerprint == "" {
			data.RequestError = "Select a key to remove."
			break
		}
		removeErr := a.sshAccounts.RemoveKey(system.SSHRemoveKeySpec{Username: site.OwnerLinuxUser, Fingerprint: fingerprint})
		if removeErr != nil {
			message := removeErr.Error()
			if errors.Is(removeErr, system.ErrSSHKeyNotFound) {
				message = "Selected SSH key was not found in authorized_keys."
			} else if errors.Is(removeErr, system.ErrInvalidUsername) {
				message = "Site owner Linux user is invalid for SSH account management."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "site.ssh_account.remove_key", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "fingerprint": fingerprint, "error": removeErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "site.ssh_account.remove_key", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser, "fingerprint": fingerprint})
		successMessage = "SSH key removed successfully."
	case "set_ssh_password":
		password := data.SSHPasswordInput
		if strings.TrimSpace(password) == "" {
			data.RequestError = "SSH password cannot be empty."
			break
		}
		pwErr := a.sshAccounts.SetPassword(system.SSHPasswordSpec{Username: site.OwnerLinuxUser, Password: password})
		if pwErr != nil {
			message := pwErr.Error()
			if errors.Is(pwErr, system.ErrInvalidLinuxPassword) {
				message = "Password cannot contain newline or colon characters and cannot be empty."
			} else if errors.Is(pwErr, system.ErrInvalidUsername) {
				message = "Site owner Linux user is invalid for SSH account management."
			} else if errors.Is(pwErr, system.ErrUserNotFound) {
				message = "Site owner Linux user does not exist on this server yet."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "site.ssh_account.set_password", site.Name, "failure", map[string]any{"run_as_user": site.OwnerLinuxUser, "error": pwErr.Error()})
			break
		}
		data.SSHPasswordInput = ""
		a.recordAudit(r.Context(), "site.ssh_account.set_password", site.Name, "success", map[string]any{"run_as_user": site.OwnerLinuxUser})
		successMessage = "SSH password updated for " + site.OwnerLinuxUser + "."
	case "select_dns_zone":
		if !a.dns.Configured() {
			data.RequestError = "AWS Route 53 credentials are not configured. Add them under Settings first."
			break
		}
		zoneID := strings.TrimSpace(data.DNSSelectedZoneID)
		zoneName := strings.TrimSpace(data.DNSSelectedZoneName)
		if zoneID == "" {
			if err := a.store.UpdateManagedSiteRoute53Zone(r.Context(), site.Name, "", ""); err != nil {
				data.RequestError = "Could not clear hosted zone: " + err.Error()
				break
			}
			site.AWSRoute53ZoneID = ""
			site.AWSRoute53ZoneName = ""
			successMessage = "Route 53 hosted zone cleared for this site."
			a.recordAudit(r.Context(), "site.dns.select_zone", site.Name, "success", map[string]any{"zone_id": ""})
			break
		}
		if zoneName == "" {
			zones, listErr := a.dns.ListHostedZones()
			if listErr != nil {
				data.RequestError = "Could not list Route 53 hosted zones: " + listErr.Error()
				break
			}
			for _, zone := range zones {
				if zone.ID == zoneID {
					zoneName = zone.Name
					break
				}
			}
		}
		if err := a.store.UpdateManagedSiteRoute53Zone(r.Context(), site.Name, zoneID, zoneName); err != nil {
			data.RequestError = "Could not save hosted zone: " + err.Error()
			break
		}
		site.AWSRoute53ZoneID = zoneID
		site.AWSRoute53ZoneName = zoneName
		a.recordAudit(r.Context(), "site.dns.select_zone", site.Name, "success", map[string]any{"zone_id": zoneID, "zone_name": zoneName})
		successMessage = "Route 53 hosted zone \"" + zoneName + "\" linked to this site."
	case "create_dns_record", "update_dns_record":
		if !a.dns.Configured() {
			data.RequestError = "AWS Route 53 credentials are not configured. Add them under Settings first."
			break
		}
		zoneID := firstNonEmpty(strings.TrimSpace(data.DNSSelectedZoneID), strings.TrimSpace(site.AWSRoute53ZoneID))
		if zoneID == "" {
			data.RequestError = "Select a Route 53 hosted zone for this site first."
			break
		}
		ttl, ttlErr := strconv.ParseInt(strings.TrimSpace(data.DNSRecordTTL), 10, 64)
		if ttlErr != nil {
			data.RequestError = "TTL must be a positive integer (seconds)."
			break
		}
		values := splitDNSRecordValues(data.DNSRecordValues)
		if len(values) == 0 {
			data.RequestError = "At least one DNS record value is required."
			break
		}
		spec := system.DNSChangeSpec{
			ZoneID: zoneID,
			Action: "UPSERT",
			Record: system.DNSRecord{
				Name:   data.DNSRecordName,
				Type:   data.DNSRecordType,
				TTL:    ttl,
				Values: values,
			},
		}
		if action == "update_dns_record" {
			spec.OldName = data.DNSRecordEditOldName
			spec.OldType = data.DNSRecordEditOldType
		}
		if err := a.dns.ApplyChange(spec); err != nil {
			message := dnsErrorMessage(err)
			data.RequestError = message
			a.recordAudit(r.Context(), "site.dns."+action, site.Name, "failure", map[string]any{"zone_id": zoneID, "name": data.DNSRecordName, "type": data.DNSRecordType, "error": err.Error()})
			break
		}
		a.recordAudit(r.Context(), "site.dns."+action, site.Name, "success", map[string]any{"zone_id": zoneID, "name": data.DNSRecordName, "type": data.DNSRecordType, "ttl": ttl, "value_count": len(values)})
		data.DNSRecordName = ""
		data.DNSRecordValues = ""
		data.DNSRecordEditOldName = ""
		data.DNSRecordEditOldType = ""
		if action == "update_dns_record" {
			successMessage = "DNS record updated successfully."
		} else {
			successMessage = "DNS record saved successfully."
		}
	case "delete_dns_record":
		if !a.dns.Configured() {
			data.RequestError = "AWS Route 53 credentials are not configured. Add them under Settings first."
			break
		}
		zoneID := firstNonEmpty(strings.TrimSpace(data.DNSSelectedZoneID), strings.TrimSpace(site.AWSRoute53ZoneID))
		if zoneID == "" {
			data.RequestError = "Select a Route 53 hosted zone for this site first."
			break
		}
		spec := system.DNSChangeSpec{
			ZoneID: zoneID,
			Action: "DELETE",
			Record: system.DNSRecord{
				Name:   firstNonEmpty(data.DNSRecordEditOldName, data.DNSRecordName),
				Type:   firstNonEmpty(data.DNSRecordEditOldType, data.DNSRecordType),
				TTL:    300,
				Values: []string{"placeholder"},
			},
		}
		if err := a.dns.ApplyChange(spec); err != nil {
			data.RequestError = dnsErrorMessage(err)
			a.recordAudit(r.Context(), "site.dns.delete_record", site.Name, "failure", map[string]any{"zone_id": zoneID, "name": spec.Record.Name, "type": spec.Record.Type, "error": err.Error()})
			break
		}
		a.recordAudit(r.Context(), "site.dns.delete_record", site.Name, "success", map[string]any{"zone_id": zoneID, "name": spec.Record.Name, "type": spec.Record.Type})
		successMessage = "DNS record deleted."
	case "refresh_dns_records":
		// no-op; data is reloaded in renderSiteDetails after the switch
	case "save_site_file":
		mode := strings.TrimSpace(r.FormValue("file_mode"))
		if err := validateFileMode(mode); err != nil {
			data.RequestError = err.Error()
			break
		}
		relPath := strings.TrimSpace(r.FormValue("file_path"))
		if relPath == "" {
			data.RequestError = "Select a file from the Files tab to edit."
			break
		}
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(site.RootDirectory, relPath)
		if resolveErr != nil {
			data.RequestError = "File path is invalid: " + resolveErr.Error()
			break
		}
		if !isEditableSiteFile(normalisedRel) {
			data.RequestError = "This file extension is not allowed in the panel editor."
			break
		}
		content := r.FormValue("file_content")
		if len(content) > 2*1024*1024 {
			data.RequestError = "File content exceeds the 2 MB editor limit."
			break
		}
		// Optional JSON validation: if the file looks like JSON,
		// reject obviously broken payloads so the operator gets a
		// fast feedback loop instead of waiting for the app to
		// blow up later.
		if strings.HasSuffix(strings.ToLower(normalisedRel), ".json") {
			trimmed := strings.TrimSpace(content)
			if trimmed != "" {
				if !json.Valid([]byte(trimmed)) {
					data.RequestError = "JSON file is not valid; fix the syntax before saving."
					data.SiteBrowserSelectedFile = normalisedRel
					data.SiteBrowserFileContent = content
					data.SiteBrowserFileEditable = true
					break
				}
			}
		}
		_, actionErr = a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":       absPath,
			"content":    content,
			"owner":      site.OwnerLinuxUser,
			"site_root":  site.RootDirectory,
			"max_bytes":  2 * 1024 * 1024,
			"create_bak": true,
			"mode":       mode,
		}, nil)
		if actionErr != nil {
			data.RequestError = "Could not save the file: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.file.save", site.Name, "failure", map[string]any{"path": normalisedRel, "error": actionErr.Error()})
			break
		}
		// Re-read so the textarea matches what's now on disk and
		// the preview tab stays in sync.
		var saved string
		if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": absPath, "max_bytes": 262144}, &saved); err == nil {
			data.SiteBrowserFileContent = saved
		} else {
			data.SiteBrowserFileContent = content
		}
		data.SiteBrowserSelectedFile = normalisedRel
		data.SiteBrowserCurrentPath = parentRelativePath(normalisedRel)
		data.SiteBrowserParentPath = parentRelativePath(data.SiteBrowserCurrentPath)
		data.SiteBrowserFileEditable = true
		a.recordAudit(r.Context(), "site.file.save", site.Name, "success", map[string]any{"path": normalisedRel, "bytes": len(content), "mode": mode})
	case "create_site_file":
		mode := strings.TrimSpace(r.FormValue("file_mode"))
		if mode == "" {
			mode = "644"
		}
		if err := validateFileMode(mode); err != nil {
			data.RequestError = err.Error()
			break
		}
		name := strings.TrimSpace(r.FormValue("new_file_name"))
		if name == "" {
			data.RequestError = "File name is required."
			break
		}
		if strings.ContainsAny(name, `/\:*?"<>|`) || strings.HasPrefix(name, ".") && !isEditableSiteFile(name) {
			data.RequestError = "File name contains invalid characters or uses a disallowed hidden extension."
			break
		}
		dir := strings.TrimSpace(r.FormValue("file_dir"))
		rel := name
		if dir != "" {
			rel = filepath.Join(dir, name)
		}
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(site.RootDirectory, rel)
		if resolveErr != nil {
			data.RequestError = "File path is invalid: " + resolveErr.Error()
			break
		}
		if !isEditableSiteFile(normalisedRel) {
			data.RequestError = "New files must use a supported text extension (json, env, yml, php, js, ...)."
			break
		}
		initial := r.FormValue("file_content")
		if len(initial) > 2*1024*1024 {
			data.RequestError = "Initial content exceeds the 2 MB editor limit."
			break
		}
		_, actionErr = a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":        absPath,
			"content":     initial,
			"owner":       site.OwnerLinuxUser,
			"site_root":   site.RootDirectory,
			"max_bytes":   2 * 1024 * 1024,
			"mode":        mode,
			"create_only": true,
		}, nil)
		if actionErr != nil {
			data.RequestError = "Could not create the file: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.file.create", site.Name, "failure", map[string]any{"path": normalisedRel, "error": actionErr.Error()})
			break
		}
		data.SiteBrowserSelectedFile = normalisedRel
		data.SiteBrowserCurrentPath = parentRelativePath(normalisedRel)
		data.SiteBrowserParentPath = parentRelativePath(data.SiteBrowserCurrentPath)
		data.SiteBrowserFileContent = initial
		data.SiteBrowserFileEditable = true
		a.recordAudit(r.Context(), "site.file.create", site.Name, "success", map[string]any{"path": normalisedRel, "mode": mode})
		successMessage = normalisedRel + " created successfully."
	case "chmod_site_file":
		mode := strings.TrimSpace(r.FormValue("file_mode"))
		if err := validateFileMode(mode); err != nil {
			data.RequestError = err.Error()
			break
		}
		if mode == "" {
			data.RequestError = "File mode is required for chmod."
			break
		}
		relPath := strings.TrimSpace(r.FormValue("file_path"))
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(site.RootDirectory, relPath)
		if resolveErr != nil || normalisedRel == "" {
			data.RequestError = "File path is invalid."
			break
		}
		// Read existing content, then write it back with the new mode.
		var current string
		if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": absPath, "max_bytes": 2 * 1024 * 1024}, &current); err != nil {
			data.RequestError = "Could not read the file to chmod: " + err.Error()
			break
		}
		_, actionErr = a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":      absPath,
			"content":   current,
			"owner":     site.OwnerLinuxUser,
			"site_root": site.RootDirectory,
			"max_bytes": 2 * 1024 * 1024,
			"mode":      mode,
		}, nil)
		if actionErr != nil {
			data.RequestError = "Could not chmod the file: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.file.chmod", site.Name, "failure", map[string]any{"path": normalisedRel, "mode": mode, "error": actionErr.Error()})
			break
		}
		a.recordAudit(r.Context(), "site.file.chmod", site.Name, "success", map[string]any{"path": normalisedRel, "mode": mode})
		successMessage = normalisedRel + " permissions set to " + mode + "."
		successMessage = normalisedRel + " saved successfully (a .bak copy was kept next to it)."
	case "save_backup_config":
		bucket := strings.TrimSpace(data.BackupS3Bucket)
		region := strings.TrimSpace(data.BackupS3Region)
		prefix := strings.TrimSpace(data.BackupS3Prefix)
		scheduleHours, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("backup_schedule_hours")))
		retentionCount, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("backup_retention_count")))
		if scheduleHours < 0 {
			scheduleHours = 0
		}
		if bucket != "" && region == "" {
			data.RequestError = "Select the AWS region for this bucket."
			break
		}
		if scheduleHours > 0 && bucket == "" {
			data.RequestError = "S3 bucket is required when scheduling backups."
			break
		}
		if retentionCount < 0 {
			retentionCount = 0
		}
		if err := a.store.UpdateManagedSiteBackupConfig(r.Context(), site.Name, bucket, region, prefix, scheduleHours, retentionCount); err != nil {
			data.RequestError = "Could not save backup configuration: " + err.Error()
			break
		}
		site.BackupS3Bucket = bucket
		site.BackupS3Region = region
		site.BackupS3Prefix = prefix
		site.BackupScheduleHours = scheduleHours
		site.BackupRetentionCount = retentionCount
		a.recordAudit(r.Context(), "site.backup.config_save", site.Name, "success", map[string]any{"bucket": bucket, "region": region, "schedule_hours": scheduleHours, "retention_count": retentionCount})
		successMessage = "Backup configuration saved."
	case "run_backup_now":
		if !a.dns.Configured() {
			data.RequestError = "AWS credentials are not configured. Add them under Settings first."
			break
		}
		if strings.TrimSpace(site.BackupS3Bucket) == "" {
			data.RequestError = "Save an S3 bucket for this site before running a backup."
			break
		}
		// Spawn the backup in the background so the request returns
		// immediately. A "running" row is inserted right away so the
		// Recent backups list shows the in-progress state. Email is
		// sent from runSiteBackup once it completes.
		siteCopy := site
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			defer cancel()
			if _, runErr := a.runSiteBackup(ctx, siteCopy, "manual"); runErr != nil {
				a.logger.Warn("manual backup failed", "site", siteCopy.Name, "error", runErr)
			}
		}()
		successMessage = "Backup started in the background. You'll get an email when it finishes; the Recent backups list refreshes on reload."
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

func (a *App) handleSubdomainDetails(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	siteName := strings.TrimSpace(r.URL.Query().Get("name"))
	subdomainIDRaw := strings.TrimSpace(r.URL.Query().Get("subdomain_id"))
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		siteName = firstNonEmpty(strings.TrimSpace(r.FormValue("site_name")), siteName)
		subdomainIDRaw = firstNonEmpty(strings.TrimSpace(r.FormValue("subdomain_id")), subdomainIDRaw)
	}
	if siteName == "" || subdomainIDRaw == "" {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}
	subdomainID, err := strconv.ParseInt(subdomainIDRaw, 10, 64)
	if err != nil || subdomainID <= 0 {
		http.Redirect(w, r, "/sites/details?name="+url.QueryEscape(siteName)+"&tab=domains", http.StatusSeeOther)
		return
	}

	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}
	subdomains, err := a.store.ListSiteSubdomains(r.Context(), site.ID)
	if err != nil {
		a.render(r.Context(), w, r.URL.Path, "sites.html", TemplateData{
			Title:          "Sites",
			DatabaseStatus: a.databaseStatus(r.Context()),
			Metrics:        a.metrics.Snapshot(),
			LinuxUsers:     a.listLinuxUsers(),
			ManagedSites:   a.listManagedSites(r),
			PHPVersions:    a.listPHPVersions(),
			RequestError:   "Subdomains could not be loaded: " + err.Error(),
		})
		return
	}
	subdomain, ok := findSiteSubdomain(subdomains, subdomainID)
	if !ok {
		http.Redirect(w, r, "/sites/details?name="+url.QueryEscape(siteName)+"&tab=domains", http.StatusSeeOther)
		return
	}

	inspectState := func(current domain.SiteSubdomain) (system.RepositoryStatus, system.RuntimeStatus, system.GitAuthStatus, []domain.DeploymentRelease, error) {
		repositoryStatus, statusErr := a.deploys.Inspect(system.RepositoryInspectSpec{TargetDirectory: current.RootDirectory, RunAsUser: site.OwnerLinuxUser})
		runtimeStatus, runtimeErr := a.runtime.Inspect(system.RuntimeInspectSpec{User: site.OwnerLinuxUser})
		repositoryURL := firstNonEmpty(current.RepositoryURL, repositoryStatus.RemoteURL)
		gitAuthStatus, gitAuthErr := a.gitAuth.Inspect(system.GitAuthInspectSpec{User: site.OwnerLinuxUser, SiteName: current.FullDomain, RepositoryURL: repositoryURL})
		releases := a.listSiteDeploymentReleases(r, current.RootDirectory, site.OwnerLinuxUser)
		if statusErr != nil {
			return repositoryStatus, runtimeStatus, gitAuthStatus, releases, fmt.Errorf("repository status could not be inspected: %w", statusErr)
		}
		if runtimeErr != nil {
			return repositoryStatus, runtimeStatus, gitAuthStatus, releases, fmt.Errorf("runtime status could not be inspected: %w", runtimeErr)
		}
		if gitAuthErr != nil {
			return repositoryStatus, runtimeStatus, gitAuthStatus, releases, fmt.Errorf("git auth status could not be inspected: %w", gitAuthErr)
		}
		return repositoryStatus, runtimeStatus, gitAuthStatus, releases, nil
	}

	repositoryStatus, runtimeStatus, gitAuthStatus, releases, inspectErr := inspectState(subdomain)
	if r.Method == http.MethodGet {
		data := TemplateData{
			SiteDetailTab: firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tab")), "overview"),
			CronFilter:    firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("cron_filter")), "subdomain"),
			CronEditID:    strings.TrimSpace(r.URL.Query().Get("cron_edit")),
			CronLogID:     strings.TrimSpace(r.URL.Query().Get("cron_log")),
		}
		if inspectErr != nil {
			data.RequestError = inspectErr.Error()
		}
		a.renderSubdomainDetails(w, r, site, subdomain, repositoryStatus, runtimeStatus, gitAuthStatus, releases, data)
		return
	}

	action := strings.TrimSpace(r.FormValue("details_action"))
	if action == "" {
		a.renderSubdomainDetails(w, r, site, subdomain, repositoryStatus, runtimeStatus, gitAuthStatus, releases, TemplateData{RequestError: "Invalid subdomain details action."})
		return
	}
	data := TemplateData{
		SiteDetailTab:                  subdomainDetailTabForAction(action),
		SubdomainDeleteID:              subdomain.ID,
		SubdomainDirectoryName:         strings.TrimSpace(r.FormValue("subdomain_directory_name")),
		SubdomainRepositoryURL:         strings.TrimSpace(r.FormValue("subdomain_repository_url")),
		SubdomainBranch:                strings.TrimSpace(r.FormValue("subdomain_branch")),
		SubdomainPostDeployCommand:     r.FormValue("subdomain_post_deploy_command"),
		SubdomainAutoDeployEnabled:     r.FormValue("subdomain_auto_deploy_enabled") == "1",
		SubdomainAutoDeployBranch:      strings.TrimSpace(r.FormValue("subdomain_auto_deploy_branch")),
		SubdomainAutoDeploySecret:      strings.TrimSpace(r.FormValue("subdomain_auto_deploy_secret")),
		SubdomainAutoDeployCommand:     r.FormValue("subdomain_auto_deploy_command"),
		SubdomainAutoDeployNodeVersion: strings.TrimSpace(r.FormValue("subdomain_auto_deploy_node_version")),
		SubdomainAutoDeployNotifyEmail: strings.TrimSpace(r.FormValue("subdomain_auto_deploy_notify_email")),
		SubdomainAutoDeployPreset:      firstNonEmpty(strings.TrimSpace(r.FormValue("subdomain_auto_deploy_preset")), "custom"),
		SubdomainAutoDeployPM2Process:  strings.TrimSpace(r.FormValue("subdomain_auto_deploy_pm2_process")),
		SubdomainTLSEmail:              strings.TrimSpace(r.FormValue("subdomain_tls_email")),
		NginxConfigContent:             r.FormValue("nginx_config_content"),
		RuntimeNodeVersion:             strings.TrimSpace(r.FormValue("node_version")),
		PreferredNodeVersion:           strings.TrimSpace(r.FormValue("preferred_node_version")),
		PM2NodeVersion:                 strings.TrimSpace(r.FormValue("pm2_node_version")),
		PM2ProcessName:                 firstNonEmpty(strings.TrimSpace(r.FormValue("process_name")), subdomain.FullDomain),
		PM2ScriptPath:                  strings.TrimSpace(r.FormValue("script_path")),
		PM2Arguments:                   strings.TrimSpace(r.FormValue("process_arguments")),
		PM2LogLines:                    firstNonEmpty(strings.TrimSpace(r.FormValue("pm2_log_lines")), "100"),
		RuntimeCommandName:             strings.TrimSpace(r.FormValue("runtime_command_name")),
		RuntimeCommandNodeVersion:      strings.TrimSpace(r.FormValue("runtime_command_node_version")),
		RuntimeCommandBody:             r.FormValue("env_content"),
		CronSchedule:                   strings.TrimSpace(r.FormValue("cron_schedule")),
		CronCommand:                    strings.TrimSpace(r.FormValue("cron_command")),
		CronRunInSiteRoot:              r.FormValue("cron_run_in_site_root") != "0",
		CronFilter:                     firstNonEmpty(strings.TrimSpace(r.FormValue("cron_filter")), "subdomain"),
		CronEditID:                     strings.TrimSpace(r.FormValue("cron_id")),
		CronLogID:                      strings.TrimSpace(r.FormValue("cron_log_id")),
		GitCredentialHost:              firstNonEmpty(strings.TrimSpace(r.FormValue("credential_host")), gitAuthStatus.RepositoryHost),
		LaravelExtraWritablePaths:      r.FormValue("laravel_extra_writable_paths"),
	}
	data.RuntimeCommandBody = firstNonEmpty(r.FormValue("runtime_command_body"), data.RuntimeCommandBody)
	if commandID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("runtime_command_id")), 10, 64); err == nil {
		data.RuntimeCommandID = commandID
	}
	data.SubdomainAutoDeployCommand = autoDeployCommandFromPreset(data.SubdomainAutoDeployPreset, firstNonEmpty(data.SubdomainAutoDeployPM2Process, data.PM2ProcessName, subdomain.FullDomain), data.SubdomainAutoDeployCommand)
	var nginxRevisionID int64
	if revisionID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("nginx_revision_id")), 10, 64); err == nil {
		nginxRevisionID = revisionID
	}

	successMessage := ""
	switch action {
	case "install_nvm":
		output, actionErr := a.runtime.InstallNVM(site.OwnerLinuxUser)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "NVM was installed for the site owner successfully."
	case "install_node":
		output, actionErr := a.runtime.InstallNode(system.NodeInstallSpec{User: site.OwnerLinuxUser, Version: strings.TrimSpace(r.FormValue("node_version")), SetDefault: r.FormValue("set_default_node") == "1"})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "Node version was installed successfully for the site owner."
	case "install_pm2":
		output, actionErr := a.runtime.InstallPM2(system.PM2InstallSpec{User: site.OwnerLinuxUser, NodeVersion: firstNonEmpty(data.PM2NodeVersion, data.PreferredNodeVersion)})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "PM2 was installed successfully for the site owner."
	case "start_pm2":
		output, actionErr := a.runtime.StartPM2(system.PM2StartSpec{User: site.OwnerLinuxUser, WorkingDirectory: subdomain.RootDirectory, ProcessName: data.PM2ProcessName, ScriptPath: data.PM2ScriptPath, Arguments: data.PM2Arguments, NodeVersion: firstNonEmpty(data.PM2NodeVersion, data.PreferredNodeVersion)})
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "PM2 process was started for this subdomain successfully."
	case "restart_pm2":
		output, actionErr := a.pm2.Restart(site.OwnerLinuxUser, data.PM2ProcessName)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "PM2 process restarted successfully."
	case "reload_pm2":
		output, actionErr := a.pm2.Reload(site.OwnerLinuxUser, data.PM2ProcessName)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "PM2 process reloaded successfully."
	case "stop_pm2":
		output, actionErr := a.pm2.Stop(site.OwnerLinuxUser, data.PM2ProcessName)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "PM2 process stopped successfully."
	case "list_pm2":
		output, actionErr := a.pm2.List(site.OwnerLinuxUser)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.PM2ListOutput = output
			break
		}
		data.PM2ListOutput = output
		successMessage = "PM2 process list loaded successfully."
	case "show_pm2_logs":
		lines, _ := strconv.Atoi(data.PM2LogLines)
		output, actionErr := a.pm2.Logs(site.OwnerLinuxUser, data.PM2ProcessName, lines)
		if actionErr != nil {
			data.RequestError = runtimeErrorMessage(actionErr)
			data.PM2LogsOutput = output
			break
		}
		data.PM2LogsOutput = output
		successMessage = "PM2 logs loaded successfully."
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
			data.RuntimeCommandNodeVersion = data.PreferredNodeVersion
		}
		commandID, err := a.store.UpsertSubdomainRuntimeCommand(r.Context(), domain.SiteRuntimeCommand{ID: data.RuntimeCommandID, SubdomainID: subdomain.ID, Name: data.RuntimeCommandName, CommandBody: data.RuntimeCommandBody, NodeVersion: data.RuntimeCommandNodeVersion})
		if err != nil {
			data.RequestError = "Could not save runtime command profile: " + err.Error()
			break
		}
		data.RuntimeCommandID = commandID
		successMessage = fmt.Sprintf("Runtime command profile \"%s\" saved.", data.RuntimeCommandName)
	case "delete_runtime_command":
		if data.RuntimeCommandID <= 0 {
			data.RequestError = "Select a saved profile to delete."
			break
		}
		if err := a.store.DeleteSubdomainRuntimeCommand(r.Context(), subdomain.ID, data.RuntimeCommandID); err != nil {
			data.RequestError = "Could not delete runtime command profile: " + err.Error()
			break
		}
		data.RuntimeCommandID = 0
		data.RuntimeCommandName = ""
		data.RuntimeCommandNodeVersion = data.PreferredNodeVersion
		data.RuntimeCommandBody = ""
		successMessage = "Runtime command profile deleted."
	case "save_subdomain_file":
		mode := strings.TrimSpace(r.FormValue("file_mode"))
		if err := validateFileMode(mode); err != nil {
			data.RequestError = err.Error()
			break
		}
		relPath := strings.TrimSpace(r.FormValue("file_path"))
		if relPath == "" {
			data.RequestError = "Select a file from the Files tab to edit."
			break
		}
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(subdomain.RootDirectory, relPath)
		if resolveErr != nil {
			data.RequestError = "File path is invalid: " + resolveErr.Error()
			break
		}
		if !isEditableSiteFile(normalisedRel) {
			data.RequestError = "This file extension is not allowed in the panel editor."
			break
		}
		content := r.FormValue("file_content")
		if len(content) > 2*1024*1024 {
			data.RequestError = "File content exceeds the 2 MB editor limit."
			break
		}
		if strings.HasSuffix(strings.ToLower(normalisedRel), ".json") {
			trimmed := strings.TrimSpace(content)
			if trimmed != "" && !json.Valid([]byte(trimmed)) {
				data.RequestError = "JSON file is not valid; fix the syntax before saving."
				data.SiteBrowserSelectedFile = normalisedRel
				data.SiteBrowserFileContent = content
				data.SiteBrowserFileEditable = true
				break
			}
		}
		_, saveErr := a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":       absPath,
			"content":    content,
			"owner":      site.OwnerLinuxUser,
			"site_root":  subdomain.RootDirectory,
			"max_bytes":  2 * 1024 * 1024,
			"create_bak": true,
			"mode":       mode,
		}, nil)
		if saveErr != nil {
			data.RequestError = "Could not save the file: " + saveErr.Error()
			a.recordAudit(r.Context(), "site.file.save", subdomain.FullDomain, "failure", map[string]any{"path": normalisedRel, "error": saveErr.Error()})
			break
		}
		var saved string
		if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": absPath, "max_bytes": 262144}, &saved); err == nil {
			data.SiteBrowserFileContent = saved
		} else {
			data.SiteBrowserFileContent = content
		}
		data.SiteBrowserSelectedFile = normalisedRel
		data.SiteBrowserCurrentPath = parentRelativePath(normalisedRel)
		data.SiteBrowserParentPath = parentRelativePath(data.SiteBrowserCurrentPath)
		data.SiteBrowserFileEditable = true
		a.recordAudit(r.Context(), "site.file.save", subdomain.FullDomain, "success", map[string]any{"path": normalisedRel, "bytes": len(content), "mode": mode})
	case "create_subdomain_file":
		mode := strings.TrimSpace(r.FormValue("file_mode"))
		if mode == "" {
			mode = "644"
		}
		if err := validateFileMode(mode); err != nil {
			data.RequestError = err.Error()
			break
		}
		name := strings.TrimSpace(r.FormValue("new_file_name"))
		if name == "" {
			data.RequestError = "File name is required."
			break
		}
		if strings.ContainsAny(name, `/\:*?"<>|`) || strings.HasPrefix(name, ".") && !isEditableSiteFile(name) {
			data.RequestError = "File name contains invalid characters or uses a disallowed hidden extension."
			break
		}
		dir := strings.TrimSpace(r.FormValue("file_dir"))
		rel := name
		if dir != "" {
			rel = filepath.Join(dir, name)
		}
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(subdomain.RootDirectory, rel)
		if resolveErr != nil {
			data.RequestError = "File path is invalid: " + resolveErr.Error()
			break
		}
		if !isEditableSiteFile(normalisedRel) {
			data.RequestError = "New files must use a supported text extension (json, env, yml, php, js, ...)."
			break
		}
		initial := r.FormValue("file_content")
		if len(initial) > 2*1024*1024 {
			data.RequestError = "Initial content exceeds the 2 MB editor limit."
			break
		}
		_, createErr := a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":        absPath,
			"content":     initial,
			"owner":       site.OwnerLinuxUser,
			"site_root":   subdomain.RootDirectory,
			"max_bytes":   2 * 1024 * 1024,
			"mode":        mode,
			"create_only": true,
		}, nil)
		if createErr != nil {
			data.RequestError = "Could not create the file: " + createErr.Error()
			a.recordAudit(r.Context(), "site.file.create", subdomain.FullDomain, "failure", map[string]any{"path": normalisedRel, "error": createErr.Error()})
			break
		}
		data.SiteBrowserSelectedFile = normalisedRel
		data.SiteBrowserCurrentPath = parentRelativePath(normalisedRel)
		data.SiteBrowserParentPath = parentRelativePath(data.SiteBrowserCurrentPath)
		data.SiteBrowserFileContent = initial
		data.SiteBrowserFileEditable = true
		a.recordAudit(r.Context(), "site.file.create", subdomain.FullDomain, "success", map[string]any{"path": normalisedRel, "mode": mode})
		successMessage = normalisedRel + " created successfully."
	case "save_node_version":
		if !validNodeVersionSelection(data.PreferredNodeVersion) {
			data.RequestError = "Node version is invalid. Use installed versions, exact semver, or aliases like lts/* or node."
			break
		}
		if err := a.store.UpdateSiteSubdomainNodeVersion(r.Context(), site.ID, subdomain.ID, strings.TrimSpace(data.PreferredNodeVersion)); err != nil {
			data.RequestError = "Could not save subdomain node version: " + err.Error()
			break
		}
		subdomain.NodeVersion = strings.TrimSpace(data.PreferredNodeVersion)
		a.recordAudit(r.Context(), "site.subdomain.node_version.save", subdomain.FullDomain, "success", map[string]any{"node_version": subdomain.NodeVersion})
		successMessage = "Subdomain node version saved."
	case "save_subdomain_deploy":
		if data.SubdomainAutoDeployPreset != "custom" && strings.TrimSpace(firstNonEmpty(data.SubdomainAutoDeployPM2Process, data.PM2ProcessName, subdomain.FullDomain)) == "" {
			data.RequestError = "Select a PM2 process name for the webhook preset action."
			break
		}
		if data.SubdomainAutoDeployEnabled && data.SubdomainAutoDeploySecret == "" {
			secret, secretErr := randomPassword(32)
			if secretErr != nil {
				data.RequestError = "Could not generate subdomain auto deploy secret."
				break
			}
			data.SubdomainAutoDeploySecret = secret
		}
		if err := a.store.UpdateSiteSubdomainDeploy(r.Context(), site.ID, subdomain.ID, data.SubdomainRepositoryURL, firstNonEmpty(data.SubdomainBranch, repositoryStatus.Branch, subdomain.BranchName, "main"), data.SubdomainPostDeployCommand, data.SubdomainAutoDeployEnabled, firstNonEmpty(data.SubdomainAutoDeployBranch, data.SubdomainBranch, subdomain.AutoDeployBranch, subdomain.BranchName, "main"), data.SubdomainAutoDeploySecret, data.SubdomainAutoDeployCommand, data.SubdomainAutoDeployNodeVersion, data.SubdomainAutoDeployNotifyEmail); err != nil {
			data.RequestError = "Could not save subdomain deploy settings: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.deploy.save", subdomain.FullDomain, "success", map[string]any{"enabled": data.SubdomainAutoDeployEnabled})
		successMessage = "Subdomain deploy settings saved."
	case "save_laravel_extra_writable_paths":
		normalizedPaths, normalizedRaw, normalizeErr := normalizeLaravelExtraWritablePathsInput(data.LaravelExtraWritablePaths)
		if normalizeErr != nil {
			data.RequestError = normalizeErr.Error()
			break
		}
		if err := a.store.UpdateSiteSubdomainLaravelExtraWritablePaths(r.Context(), site.ID, subdomain.ID, normalizedRaw); err != nil {
			data.RequestError = "Could not save subdomain Laravel extra writable paths: " + err.Error()
			break
		}
		data.LaravelExtraWritablePaths = normalizedRaw
		subdomain.LaravelExtraWritablePaths = normalizedRaw
		a.recordAudit(r.Context(), "site.subdomain.laravel_paths.save", subdomain.FullDomain, "success", map[string]any{"paths": normalizedPaths})
		successMessage = "Subdomain Laravel extra writable paths saved."
	case "rotate_subdomain_auto_deploy_secret":
		if data.SubdomainAutoDeployPreset != "custom" && strings.TrimSpace(firstNonEmpty(data.SubdomainAutoDeployPM2Process, data.PM2ProcessName, subdomain.FullDomain)) == "" {
			data.RequestError = "Select a PM2 process name for the webhook preset action."
			break
		}
		secret, secretErr := randomPassword(32)
		if secretErr != nil {
			data.RequestError = "Could not rotate subdomain auto deploy secret."
			break
		}
		data.SubdomainAutoDeploySecret = secret
		if err := a.store.UpdateSiteSubdomainDeploy(r.Context(), site.ID, subdomain.ID, firstNonEmpty(data.SubdomainRepositoryURL, subdomain.RepositoryURL), firstNonEmpty(data.SubdomainBranch, subdomain.BranchName, repositoryStatus.Branch, "main"), firstNonEmpty(data.SubdomainPostDeployCommand, subdomain.PostDeployCommand), data.SubdomainAutoDeployEnabled || subdomain.AutoDeployEnabled, firstNonEmpty(data.SubdomainAutoDeployBranch, subdomain.AutoDeployBranch, subdomain.BranchName, "main"), secret, firstNonEmpty(data.SubdomainAutoDeployCommand, subdomain.AutoDeployCommand), firstNonEmpty(data.SubdomainAutoDeployNodeVersion, subdomain.AutoDeployNodeVersion), firstNonEmpty(data.SubdomainAutoDeployNotifyEmail, subdomain.AutoDeployNotifyEmail)); err != nil {
			data.RequestError = "Could not rotate subdomain auto deploy secret: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.deploy.rotate_secret", subdomain.FullDomain, "success", nil)
		successMessage = "Subdomain auto deploy secret rotated."
	case "create_cron_job":
		output, actionErr := a.helper.Call(r.Context(), "cron.create", system.CronJobSpec{
			User:             site.OwnerLinuxUser,
			Schedule:         data.CronSchedule,
			Command:          data.CronCommand,
			SiteName:         subdomain.FullDomain,
			WorkingDirectory: subdomain.RootDirectory,
			RunInSiteRoot:    data.CronRunInSiteRoot,
		}, nil)
		if actionErr != nil {
			message := actionErr.Error()
			switch {
			case errors.Is(actionErr, system.ErrInvalidUsername):
				message = "Subdomain owner Linux user is invalid for cron management."
			case errors.Is(actionErr, system.ErrInvalidCronSchedule):
				message = "Cron schedule must be a standard 5-field expression or a supported @shortcut."
			case errors.Is(actionErr, system.ErrInvalidCronCommand):
				message = "Cron command cannot be empty."
			case errors.Is(actionErr, system.ErrInvalidTargetDirectory):
				message = "Subdomain root directory is invalid for run-in-root cron jobs."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "site.subdomain.cron.create", subdomain.FullDomain, "failure", map[string]any{"user": site.OwnerLinuxUser, "schedule": data.CronSchedule, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.subdomain.cron.create", subdomain.FullDomain, "success", map[string]any{"user": site.OwnerLinuxUser, "schedule": data.CronSchedule, "run_in_site_root": data.CronRunInSiteRoot})
		data.CronSchedule = ""
		data.CronCommand = ""
		data.CronRunInSiteRoot = true
		successMessage = "Cron job created for the subdomain successfully."
	case "update_cron_job":
		if strings.TrimSpace(data.CronEditID) == "" {
			data.RequestError = "Select a panel-managed cron job for this subdomain to edit."
			break
		}
		output, actionErr := a.helper.Call(r.Context(), "cron.update", system.CronJobUpdateSpec{
			User:             site.OwnerLinuxUser,
			ID:               data.CronEditID,
			Schedule:         data.CronSchedule,
			Command:          data.CronCommand,
			SiteName:         subdomain.FullDomain,
			WorkingDirectory: subdomain.RootDirectory,
			RunInSiteRoot:    data.CronRunInSiteRoot,
		}, nil)
		if actionErr != nil {
			message := actionErr.Error()
			switch {
			case errors.Is(actionErr, system.ErrInvalidUsername):
				message = "Subdomain owner Linux user is invalid for cron management."
			case errors.Is(actionErr, system.ErrInvalidCronSchedule):
				message = "Cron schedule must be a standard 5-field expression or a supported @shortcut."
			case errors.Is(actionErr, system.ErrInvalidCronCommand):
				message = "Cron command cannot be empty."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "site.subdomain.cron.update", subdomain.FullDomain, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": data.CronEditID, "schedule": data.CronSchedule, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.subdomain.cron.update", subdomain.FullDomain, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": data.CronEditID, "schedule": data.CronSchedule, "run_in_site_root": data.CronRunInSiteRoot})
		data.CronEditID = ""
		data.CronSchedule = ""
		data.CronCommand = ""
		data.CronRunInSiteRoot = true
		successMessage = "Cron job updated successfully."
	case "delete_cron_job":
		cronRawLine := strings.TrimSpace(r.FormValue("cron_raw_line"))
		cronID := strings.TrimSpace(r.FormValue("cron_id"))
		output, actionErr := a.helper.Call(r.Context(), "cron.delete", system.CronJobDeleteSpec{User: site.OwnerLinuxUser, ID: cronID, RawLine: cronRawLine}, nil)
		if actionErr != nil {
			data.RequestError = "Cron job could not be deleted: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.subdomain.cron.delete", subdomain.FullDomain, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		a.recordAudit(r.Context(), "site.subdomain.cron.delete", subdomain.FullDomain, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID})
		successMessage = "Cron job deleted successfully."
	case "clear_cron_log":
		cronID := strings.TrimSpace(r.FormValue("cron_id"))
		data.CronLogID = cronID
		output, actionErr := a.helper.Call(r.Context(), "cron.clear_log", map[string]string{"user": site.OwnerLinuxUser, "id": cronID}, nil)
		if actionErr != nil {
			data.RequestError = "Cron log could not be cleared: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.subdomain.cron.clear_log", subdomain.FullDomain, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		data.CronLogNotice = "Cron log was cleared."
		a.recordAudit(r.Context(), "site.subdomain.cron.clear_log", subdomain.FullDomain, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID})
		successMessage = "Cron log cleared successfully."
	case "rotate_cron_log":
		cronID := strings.TrimSpace(r.FormValue("cron_id"))
		data.CronLogID = cronID
		output, actionErr := a.helper.Call(r.Context(), "cron.rotate_log", map[string]string{"user": site.OwnerLinuxUser, "id": cronID}, nil)
		if actionErr != nil {
			data.RequestError = "Cron log could not be rotated: " + actionErr.Error()
			a.recordAudit(r.Context(), "site.subdomain.cron.rotate_log", subdomain.FullDomain, "failure", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "error": actionErr.Error()})
			break
		}
		data.CommandOutput = output
		data.CronLogNotice = "Cron log was rotated to: " + output
		a.recordAudit(r.Context(), "site.subdomain.cron.rotate_log", subdomain.FullDomain, "success", map[string]any{"user": site.OwnerLinuxUser, "cron_id": cronID, "rotated_path": output})
		successMessage = "Cron log rotated successfully."
	case "move_subdomain_root_preview":
		preview := a.inspectSubdomainMovePreview(r.Context(), site, subdomain, firstNonEmpty(data.SubdomainDirectoryName, subdomain.Subdomain))
		data.PreviewSubdomainID = subdomain.ID
		data.SubdomainMovePreviewFrom = preview.From
		data.SubdomainMovePreviewTo = preview.To
		data.SubdomainMovePreviewTargetExists = preview.TargetExists
		data.SubdomainMovePreviewTargetEmpty = preview.TargetEmpty
		data.SubdomainMovePreviewTargetGitRepo = preview.TargetGitRepo
		data.SubdomainMovePreviewTargetState = preview.TargetState
		successMessage = "Move preview updated."
	case "move_subdomain_root":
		newRoot := buildManagedSubdomainRootDirectory(site, a.cfg.SubdomainRootBaseDir, firstNonEmpty(data.SubdomainDirectoryName, subdomain.Subdomain))
		if filepath.Clean(newRoot) == filepath.Clean(subdomain.RootDirectory) {
			data.RequestError = "Subdomain root is already set to that directory."
			break
		}
		moveScript := "set -e; mkdir -p $(dirname " + shellSingleQuote(newRoot) + "); if [ -e " + shellSingleQuote(newRoot) + " ]; then echo 'Destination already exists'; exit 1; fi; if [ -e " + shellSingleQuote(subdomain.RootDirectory) + " ]; then mv " + shellSingleQuote(subdomain.RootDirectory) + " " + shellSingleQuote(newRoot) + "; else mkdir -p " + shellSingleQuote(newRoot) + "; fi"
		output, actionErr := a.helper.Call(r.Context(), "runtime.run_shell_command", system.ShellCommandSpec{User: site.OwnerLinuxUser, WorkingDirectory: filepath.Dir(subdomain.RootDirectory), CommandBody: moveScript}, nil)
		if actionErr != nil {
			data.RequestError = "Could not move subdomain root: " + actionErr.Error()
			data.CommandOutput = output
			break
		}
		siteSpec := buildSubdomainSiteSpec(site, subdomain, newRoot)
		configPath, actionErr := a.nginx.ApplySite(siteSpec)
		if actionErr != nil {
			data.RequestError = "Subdomain files moved but Nginx config could not be updated: " + actionErr.Error()
			data.CommandOutput = output
			break
		}
		if err := a.store.UpdateSiteSubdomainLocation(r.Context(), site.ID, subdomain.ID, newRoot, configPath); err != nil {
			data.RequestError = "Subdomain root moved but store update failed: " + err.Error()
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "Subdomain root directory moved successfully."
	case "rollback_subdomain_release":
		releaseCommit := strings.TrimSpace(r.FormValue("release_commit_sha"))
		if releaseCommit == "" {
			data.RequestError = "Release commit is required for rollback."
			break
		}
		result, actionErr := a.deploys.Rollback(system.RollbackSpec{TargetDirectory: subdomain.RootDirectory, RunAsUser: site.OwnerLinuxUser, ReleaseCommitSHA: releaseCommit, PostDeployCommand: firstNonEmpty(strings.TrimSpace(r.FormValue("rollback_post_deploy_command")), subdomain.PostDeployCommand), PostDeployNodeVersion: strings.TrimSpace(subdomain.NodeVersion)})
		if actionErr != nil {
			data.RequestError = actionErr.Error()
			data.CommandOutput = result.Output
			break
		}
		if a.store != nil {
			_ = a.store.CreateDeploymentRelease(r.Context(), domain.DeploymentRelease{RepositoryURL: subdomain.RepositoryURL, BranchName: "rollback", TargetDirectory: subdomain.RootDirectory, RunAsUser: site.OwnerLinuxUser, Action: result.Action, Status: "success", CommitSHA: result.CommitSHA, PreviousCommitSHA: result.PreviousCommitSHA, Output: result.Output})
		}
		data.CommandOutput = result.Output
		successMessage = "Subdomain rollback completed successfully."
	case "enable_subdomain_tls":
		if data.SubdomainTLSEmail == "" {
			data.RequestError = "TLS email is required for the subdomain certificate."
			break
		}
		output, actionErr := a.nginx.EnableTLS(system.TLSRequest{Domain: subdomain.FullDomain, AdditionalDomains: parseAdditionalDomains(r.FormValue("subdomain_tls_additional_domains")), Email: data.SubdomainTLSEmail, Redirect: r.FormValue("subdomain_tls_redirect") == "1", ConfigPath: strings.TrimSpace(subdomain.NginxConfigPath)})
		if actionErr != nil {
			data.RequestError = "Could not enable TLS for subdomain: " + actionErr.Error()
			data.CommandOutput = output
			break
		}
		data.CommandOutput = output
		successMessage = "Subdomain TLS enabled successfully."
	case "edit_subdomain_env":
		envPath, _, pathErr := resolveSiteBrowserPath(subdomain.RootDirectory, ".env")
		if pathErr != nil {
			data.RequestError = "Invalid .env file path."
			break
		}
		if _, err := a.helper.Call(r.Context(), "files.write_env", map[string]string{"path": envPath, "content": r.FormValue("env_content"), "owner": site.OwnerLinuxUser}, nil); err != nil {
			data.RequestError = "Could not write .env file: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.edit_env", subdomain.FullDomain, "success", nil)
		successMessage = ".env file saved successfully."
	case "save_nginx_config":
		configPath, targetLabel, _, subdomainTargetID, err := resolveNginxConfigTarget(site, subdomains, "subdomain", subdomain.ID)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		if !isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, configPath) {
			data.RequestError = "Stored Nginx config path is outside the allowed Nginx config directory."
			break
		}
		if err := a.saveNginxConfigContent(r.Context(), site, subdomainTargetID, configPath, data.NginxConfigContent, true); err != nil {
			data.RequestError = err.Error()
			break
		}
		data.NginxConfigNotice = "Nginx config saved, validated, and reloaded successfully."
		a.recordAudit(r.Context(), "site.nginx_config.save", targetLabel, "success", map[string]any{"config_path": configPath, "target_type": "subdomain", "subdomain_id": subdomainTargetID})
		successMessage = "Nginx config updated successfully."
	case "validate_nginx_config":
		configPath, targetLabel, _, subdomainTargetID, err := resolveNginxConfigTarget(site, subdomains, "subdomain", subdomain.ID)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		output, actionErr := a.helper.Call(r.Context(), "nginx.validate_config", map[string]string{"path": configPath, "content": data.NginxConfigContent}, nil)
		if actionErr != nil {
			data.RequestError = "Nginx config validation failed: " + actionErr.Error()
			break
		}
		data.CommandOutput = output
		data.NginxConfigNotice = "Validation passed. No file was changed."
		a.recordAudit(r.Context(), "site.nginx_config.validate", targetLabel, "success", map[string]any{"config_path": configPath, "target_type": "subdomain", "subdomain_id": subdomainTargetID})
		successMessage = "Nginx config validated successfully."
	case "rollback_nginx_config":
		configPath, targetLabel, _, subdomainTargetID, err := resolveNginxConfigTarget(site, subdomains, "subdomain", subdomain.ID)
		if err != nil {
			data.RequestError = err.Error()
			break
		}
		if nginxRevisionID <= 0 {
			data.RequestError = "Select a saved Nginx config revision to roll back."
			break
		}
		revision, err := a.store.GetNginxConfigRevision(r.Context(), nginxRevisionID, site.ID, subdomainTargetID)
		if err != nil {
			data.RequestError = "Could not load Nginx config revision: " + err.Error()
			break
		}
		if revision.ConfigPath != configPath {
			data.RequestError = "Selected revision does not belong to this Nginx config target."
			break
		}
		data.NginxConfigContent = revision.Content
		if err := a.saveNginxConfigContent(r.Context(), site, subdomainTargetID, configPath, revision.Content, true); err != nil {
			data.RequestError = err.Error()
			break
		}
		data.NginxConfigNotice = "Selected Nginx config revision was restored successfully."
		a.recordAudit(r.Context(), "site.nginx_config.rollback", targetLabel, "success", map[string]any{"config_path": configPath, "revision_id": nginxRevisionID, "target_type": "subdomain", "subdomain_id": subdomainTargetID})
		successMessage = "Nginx config rollback completed successfully."
	case "delete_subdomain":
		if err := a.nginx.DeleteSite(system.SiteRemoval{Name: subdomainConfigName(site.Name, subdomain.FullDomain), Domain: subdomain.FullDomain, RootDirectory: subdomain.RootDirectory, ConfigPath: subdomain.NginxConfigPath}); err != nil {
			data.RequestError = "Could not delete subdomain from Nginx: " + err.Error()
			break
		}
		if err := a.store.DeleteSiteSubdomain(r.Context(), site.ID, subdomain.ID); err != nil {
			data.RequestError = "Subdomain Nginx config was removed but panel record could not be deleted: " + err.Error()
			break
		}
		a.recordAudit(r.Context(), "site.subdomain.delete", subdomain.FullDomain, "success", nil)
		http.Redirect(w, r, "/sites/details?name="+url.QueryEscape(site.Name)+"&tab=domains", http.StatusSeeOther)
		return
	default:
		data.RequestError = "Invalid subdomain details action."
	}

	subdomains, _ = a.store.ListSiteSubdomains(r.Context(), site.ID)
	subdomain, ok = findSiteSubdomain(subdomains, subdomainID)
	if !ok {
		http.Redirect(w, r, "/sites/details?name="+url.QueryEscape(site.Name)+"&tab=domains", http.StatusSeeOther)
		return
	}
	repositoryStatus, runtimeStatus, gitAuthStatus, releases, inspectErr = inspectState(subdomain)
	if successMessage != "" {
		data.SuccessMessage = successMessage
	}
	if data.RequestError == "" && inspectErr != nil {
		data.RequestError = inspectErr.Error()
	}
	a.renderSubdomainDetails(w, r, site, subdomain, repositoryStatus, runtimeStatus, gitAuthStatus, releases, data)
}

func (a *App) handleDeploys(w http.ResponseWriter, r *http.Request) {
	users := a.listLinuxUsers()
	nodeVersionOptions := a.collectDeployNodeVersionOptions(users)
	releases := []domain.DeploymentRelease{}
	if a.store != nil {
		if entries, err := a.store.ListDeploymentReleases(r.Context(), 12); err == nil {
			releases = entries
		}
	}

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
			Title:              "Deploys",
			DatabaseStatus:     a.databaseStatus(r.Context()),
			Metrics:            a.metrics.Snapshot(),
			LinuxUsers:         users,
			NodeVersionOptions: nodeVersionOptions,
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
			Title:              "Deploys",
			DatabaseStatus:     a.databaseStatus(r.Context()),
			Metrics:            a.metrics.Snapshot(),
			LinuxUsers:         users,
			NodeVersionOptions: nodeVersionOptions,
			RequestError:       "The submitted deploy form could not be parsed.",
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
		RepositoryURL:         r.FormValue("repository_url"),
		Branch:                r.FormValue("branch"),
		TargetDirectory:       r.FormValue("target_directory"),
		RunAsUser:             r.FormValue("run_as_user"),
		GitSiteName:           r.FormValue("git_site_name"),
		PostDeployCommand:     r.FormValue("post_deploy_command"),
		PostDeployNodeVersion: strings.TrimSpace(r.FormValue("post_deploy_node_version")),
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
			Title:              "Deploys",
			DatabaseStatus:     a.databaseStatus(r.Context()),
			Metrics:            a.metrics.Snapshot(),
			LinuxUsers:         users,
			NodeVersionOptions: nodeVersionOptions,
			DeployNodeVersion:  spec.PostDeployNodeVersion,
			RequestError:       message,
			CommandOutput:      result.Output,
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
			RepositoryURL:   spec.RepositoryURL,
			BranchName:      branch,
			TargetDirectory: spec.TargetDirectory,
			RunAsUser:       spec.RunAsUser,
			LastStatus:      "success",
			LastOutput:      result.Output,
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
		Title:              "Deploys",
		DatabaseStatus:     a.databaseStatus(r.Context()),
		Metrics:            a.metrics.Snapshot(),
		LinuxUsers:         users,
		NodeVersionOptions: nodeVersionOptions,
		DeployNodeVersion:  spec.PostDeployNodeVersion,
		SuccessMessage:     "Repository deploy completed successfully.",
		ResultPath:         spec.TargetDirectory,
		CommandOutput:      result.Output,
		CommitSHA:          result.CommitSHA,
		PreviousCommitSHA:  result.PreviousCommitSHA,
		DeploymentReleases: releases,
	})
}

func (a *App) handleDeployRollback(w http.ResponseWriter, r *http.Request, users []system.LinuxUser, releases []domain.DeploymentRelease) {
	nodeVersionOptions := a.collectDeployNodeVersionOptions(users)
	spec := system.RollbackSpec{
		TargetDirectory:       r.FormValue("rollback_target_directory"),
		RunAsUser:             r.FormValue("rollback_run_as_user"),
		ReleaseCommitSHA:      r.FormValue("release_commit_sha"),
		PostDeployCommand:     r.FormValue("rollback_post_deploy_command"),
		PostDeployNodeVersion: strings.TrimSpace(r.FormValue("rollback_post_deploy_node_version")),
	}

	result, err := a.deploys.Rollback(spec)
	if err != nil {
		a.recordAudit(r.Context(), "deploy.rollback", spec.TargetDirectory, "failure", map[string]any{"run_as_user": spec.RunAsUser, "commit_sha": spec.ReleaseCommitSHA, "error": err.Error()})
		a.render(r.Context(), w, r.URL.Path, "deploys.html", TemplateData{
			Title:               "Deploys",
			DatabaseStatus:      a.databaseStatus(r.Context()),
			Metrics:             a.metrics.Snapshot(),
			LinuxUsers:          users,
			NodeVersionOptions:  nodeVersionOptions,
			RollbackNodeVersion: spec.PostDeployNodeVersion,
			RequestError:        err.Error(),
			CommandOutput:       result.Output,
			DeploymentReleases:  releases,
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
		Title:               "Deploys",
		DatabaseStatus:      a.databaseStatus(r.Context()),
		Metrics:             a.metrics.Snapshot(),
		LinuxUsers:          users,
		NodeVersionOptions:  nodeVersionOptions,
		RollbackNodeVersion: spec.PostDeployNodeVersion,
		SuccessMessage:      "Rollback completed successfully.",
		ResultPath:          spec.TargetDirectory,
		CommandOutput:       result.Output,
		CommitSHA:           result.CommitSHA,
		PreviousCommitSHA:   result.PreviousCommitSHA,
		DeploymentReleases:  releases,
	})
}

func (a *App) renderSiteDetails(w http.ResponseWriter, r *http.Request, site domain.ManagedSite, repositoryStatus system.RepositoryStatus, runtimeStatus system.RuntimeStatus, gitAuthStatus system.GitAuthStatus, releases []domain.DeploymentRelease, data TemplateData) {
	data.Title = site.Name + " details"
	data.DatabaseStatus = a.databaseStatus(r.Context())
	data.Metrics = a.metrics.Snapshot()
	data.SelectedSite = site
	data.SubdomainRootBaseDir = strings.TrimSpace(a.cfg.SubdomainRootBaseDir)
	if data.SiteDetailTab == "" {
		data.SiteDetailTab = "overview"
	}
	data.RepositoryStatus = repositoryStatus
	data.RuntimeStatus = runtimeStatus
	data.GitAuthStatus = gitAuthStatus
	data.DeploymentReleases = releases
	data.PreferredNodeVersion = firstNonEmpty(data.PreferredNodeVersion, site.NodeVersion)
	data.AutoDeployEnabled = data.AutoDeployEnabled || site.AutoDeployEnabled
	data.AutoDeployBranch = firstNonEmpty(data.AutoDeployBranch, site.AutoDeployBranch, repositoryStatus.Branch)
	data.AutoDeploySecret = firstNonEmpty(data.AutoDeploySecret, site.AutoDeploySecret)
	data.AutoDeployCommand = firstNonEmpty(data.AutoDeployCommand, site.AutoDeployCommand)
	data.AutoDeployNodeVersion = firstNonEmpty(data.AutoDeployNodeVersion, site.AutoDeployNodeVersion, data.PreferredNodeVersion)
	data.AutoDeployNotifyEmail = firstNonEmpty(data.AutoDeployNotifyEmail, site.AutoDeployNotifyEmail)
	data.AutoDeployWebhookURL = buildAutoDeployWebhookURL(requestExternalBaseURL(r, a.cfg.BaseURL), site.Name, data.AutoDeploySecret)
	data.AutoDeployWebhookAuthHint = autoDeployWebhookAuthHint()
	if len(releases) > 0 {
		data.LatestDeploymentRelease = releases[0]
	}
	data.PackageScripts = readPackageJSONScripts(site.RootDirectory)
	data.ProjectHasComposer, data.ProjectHasArtisan = a.detectProjectMarkers(r.Context(), site.RootDirectory)
	data.DeployCommandPlaceholder = recommendedDeployCommand(data.ProjectHasComposer, data.ProjectHasArtisan, data.PackageScripts, site.Name)
	data.AutoDeployCommandPlaceholder = data.DeployCommandPlaceholder
	data.NpmScriptNodeVersion = firstNonEmpty(data.NpmScriptNodeVersion, data.PreferredNodeVersion)
	if data.RuntimeCommandNodeVersion == "" {
		data.RuntimeCommandNodeVersion = data.PreferredNodeVersion
	}
	data.DatabaseAccess, _ = a.databases.ListDatabaseAccess()
	data.LinuxUsers = a.listLinuxUsers()
	if strings.TrimSpace(site.OwnerLinuxUser) != "" {
		if status, err := a.sshAccounts.Inspect(site.OwnerLinuxUser); err == nil {
			data.SSHAccountStatus = status
		}
	}
	if data.BackupS3Bucket == "" {
		data.BackupS3Bucket = site.BackupS3Bucket
	}
	if data.BackupS3Region == "" {
		data.BackupS3Region = site.BackupS3Region
	}
	if data.BackupS3Prefix == "" {
		data.BackupS3Prefix = site.BackupS3Prefix
	}
	if data.BackupScheduleHours == 0 {
		data.BackupScheduleHours = site.BackupScheduleHours
	}
	if data.BackupRetentionCount == 0 {
		data.BackupRetentionCount = site.BackupRetentionCount
		if data.BackupRetentionCount == 0 {
			data.BackupRetentionCount = 7
		}
	}
	if a.store != nil {
		if backups, err := a.store.ListSiteBackups(r.Context(), site.ID, 25); err == nil {
			data.BackupHistory = backups
		}
	}
	data.AWSConfigured = a.dns.Configured()
	data.DNSEnabled = a.dns.Configured()
	if data.DNSEnabled {
		if zones, err := a.dns.ListHostedZones(); err == nil {
			data.DNSZones = zones
		} else {
			data.DNSError = "Could not load Route 53 hosted zones: " + err.Error()
		}
		selectedZoneID := firstNonEmpty(strings.TrimSpace(data.DNSSelectedZoneID), strings.TrimSpace(site.AWSRoute53ZoneID))
		if selectedZoneID != "" {
			data.DNSSelectedZoneID = selectedZoneID
			if data.DNSSelectedZoneName == "" {
				data.DNSSelectedZoneName = site.AWSRoute53ZoneName
				for _, zone := range data.DNSZones {
					if zone.ID == selectedZoneID {
						data.DNSSelectedZoneName = zone.Name
						break
					}
				}
			}
			if records, err := a.dns.ListRecords(selectedZoneID); err == nil {
				data.DNSRecords = records
			} else if data.DNSError == "" {
				data.DNSError = "Could not load DNS records: " + err.Error()
			}
			if data.DNSRecordEditOldName != "" && data.DNSRecordEditOldType != "" {
				for _, record := range data.DNSRecords {
					if strings.EqualFold(record.Name, data.DNSRecordEditOldName) && strings.EqualFold(record.Type, data.DNSRecordEditOldType) {
						data.DNSEditing = true
						if data.DNSRecordName == "" {
							data.DNSRecordName = record.Name
						}
						if data.DNSRecordType == "" {
							data.DNSRecordType = record.Type
						}
						if data.DNSRecordTTL == "" {
							data.DNSRecordTTL = strconv.FormatInt(record.TTL, 10)
						}
						if data.DNSRecordValues == "" {
							data.DNSRecordValues = strings.Join(record.Values, "\n")
						}
						break
					}
				}
			}
		}
	}
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
	for index := range data.SiteSubdomains {
		if strings.TrimSpace(data.SiteSubdomains[index].AutoDeployBranch) == "" {
			data.SiteSubdomains[index].AutoDeployBranch = strings.TrimSpace(data.SiteSubdomains[index].BranchName)
		}
		data.SiteSubdomains[index].AutoDeployWebhookURL = buildSubdomainAutoDeployWebhookURL(requestExternalBaseURL(r, a.cfg.BaseURL), site.Name, data.SiteSubdomains[index].ID, data.SiteSubdomains[index].AutoDeploySecret)
		data.SiteSubdomains[index].DeploymentReleases = a.listSiteDeploymentReleases(r, data.SiteSubdomains[index].RootDirectory, site.OwnerLinuxUser)
		if gitAuthStatus, err := a.gitAuth.Inspect(system.GitAuthInspectSpec{User: site.OwnerLinuxUser, SiteName: data.SiteSubdomains[index].FullDomain, RepositoryURL: data.SiteSubdomains[index].RepositoryURL}); err == nil {
			data.SiteSubdomains[index].GitAuthStatus = gitAuthStatus
		}
		if entry, err := a.store.GetLatestAuditLogByActionAndTarget(r.Context(), "deploy.webhook", data.SiteSubdomains[index].FullDomain); err == nil {
			entry.Metadata = summarizeAuditMetadata(entry.Metadata)
			data.SiteSubdomains[index].LatestWebhookAudit = entry
		}
		if data.PreviewSubdomainID == data.SiteSubdomains[index].ID {
			data.SiteSubdomains[index].MovePreviewFrom = data.SubdomainMovePreviewFrom
			data.SiteSubdomains[index].MovePreviewTo = data.SubdomainMovePreviewTo
			data.SiteSubdomains[index].MovePreviewTargetExists = data.SubdomainMovePreviewTargetExists
			data.SiteSubdomains[index].MovePreviewTargetEmpty = data.SubdomainMovePreviewTargetEmpty
			data.SiteSubdomains[index].MovePreviewTargetGitRepo = data.SubdomainMovePreviewTargetGitRepo
			data.SiteSubdomains[index].MovePreviewTargetState = data.SubdomainMovePreviewTargetState
		}
	}
	if data.CronFilter == "" {
		data.CronFilter = "site"
	}
	var allCronJobs []system.CronJob
	if _, err := a.helper.Call(r.Context(), "cron.list", map[string]string{"user": site.OwnerLinuxUser}, &allCronJobs); err == nil {
		filteredJobs := make([]system.CronJob, 0, len(allCronJobs))
		for _, job := range allCronJobs {
			job.NextRunText = describeCronNextRun(job.Schedule, time.Now())
			if data.CronFilter == "all" {
				filteredJobs = append(filteredJobs, job)
				continue
			}
			if job.Managed && job.SiteName == site.Name {
				filteredJobs = append(filteredJobs, job)
			}
		}
		data.CronJobs = filteredJobs
		for _, job := range allCronJobs {
			if data.CronEditID != "" && job.Managed && job.SiteName == site.Name && job.ID == data.CronEditID {
				data.CronSchedule = firstNonEmpty(data.CronSchedule, job.Schedule)
				data.CronCommand = firstNonEmpty(data.CronCommand, job.Command)
				data.CronRunInSiteRoot = job.RunInSiteRoot
			}
			if data.CronLogID != "" && job.ID == data.CronLogID && job.LogPath != "" {
				data.CronLogTitle = firstNonEmpty(job.SiteName, site.Name) + " · " + job.Schedule
				var logContent string
				if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": job.LogPath, "max_bytes": 65536}, &logContent); err == nil {
					data.CronLogContent = logContent
					if data.CronLogNotice == "" && strings.Contains(logContent, "[truncated after ") {
						data.CronLogNotice = "Only the last available 64 KB of the cron log is shown."
					}
				} else if data.CronLogNotice == "" {
					data.CronLogNotice = "Cron log file could not be read yet. The job may not have run yet."
				}
			}
		}
	}
	data.NginxConfigPath = strings.TrimSpace(site.NginxConfigPath)
	if data.NginxConfigPath != "" {
		editor := SiteNginxConfigEditor{TargetType: "site", Title: site.Name, Domain: site.DomainName, TargetID: 0, ConfigPath: data.NginxConfigPath, Notice: data.NginxConfigNotice}
		if isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, editor.ConfigPath) {
			var content string
			if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": editor.ConfigPath, "max_bytes": 1048576}, &content); err == nil {
				editor.Content = content
				if strings.Contains(content, "[truncated after ") {
					editor.Notice = firstNonEmpty(editor.Notice, "Only the first 1 MB of the Nginx config is shown.")
				}
			}
			if targetType := strings.TrimSpace(r.FormValue("nginx_target_type")); targetType == "site" || targetType == "" {
				if data.NginxConfigContent != "" {
					editor.Content = data.NginxConfigContent
				}
			}
			if revisions, err := a.store.ListNginxConfigRevisions(r.Context(), site.ID, 0, 8); err == nil {
				editor.Revisions = revisions
			}
		} else {
			editor.Notice = firstNonEmpty(editor.Notice, "Stored Nginx config path is outside the managed Nginx directory and cannot be edited from the panel.")
		}
		data.NginxEditors = append(data.NginxEditors, editor)
	}
	for _, subdomain := range data.SiteSubdomains {
		editor := SiteNginxConfigEditor{TargetType: "subdomain", TargetID: subdomain.ID, Title: subdomain.FullDomain, Domain: subdomain.FullDomain, ConfigPath: strings.TrimSpace(subdomain.NginxConfigPath)}
		if editor.ConfigPath == "" {
			continue
		}
		if isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, editor.ConfigPath) {
			var content string
			if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": editor.ConfigPath, "max_bytes": 1048576}, &content); err == nil {
				editor.Content = content
				if strings.Contains(content, "[truncated after ") {
					editor.Notice = firstNonEmpty(editor.Notice, "Only the first 1 MB of the Nginx config is shown.")
				}
			}
			if strings.TrimSpace(r.FormValue("nginx_target_type")) == "subdomain" && data.NginxConfigContent != "" {
				if targetID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("nginx_target_id")), 10, 64); err == nil && targetID == subdomain.ID {
					editor.Content = data.NginxConfigContent
				}
			}
			if revisions, err := a.store.ListNginxConfigRevisions(r.Context(), site.ID, subdomain.ID, 8); err == nil {
				editor.Revisions = revisions
			}
		} else {
			editor.Notice = "Stored Nginx config path is outside the managed Nginx directory and cannot be edited from the panel."
		}
		data.NginxEditors = append(data.NginxEditors, editor)
	}
	browserPath := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("path")), data.SiteBrowserCurrentPath)
	if absPath, relPath, err := resolveSiteBrowserPath(site.RootDirectory, browserPath); err == nil {
		data.SiteBrowserCurrentPath = relPath
		data.SiteBrowserParentPath = parentRelativePath(relPath)
		var helperEntries []helperSiteFileEntry
		if _, err := a.helper.Call(r.Context(), "files.list_dir", map[string]string{"path": absPath}, &helperEntries); err == nil {
			entries := make([]SiteFileEntry, 0, len(helperEntries))
			for _, entry := range helperEntries {
				rel := filepath.Join(relPath, entry.Name)
			entries = append(entries, SiteFileEntry{
				Name:          entry.Name,
				RelativePath:  rel,
				IsDir:         entry.IsDir,
				Size:          entry.Size,
				IsSymlink:     entry.IsSymlink,
				SymlinkTarget: entry.SymlinkTarget,
				Editable:      !entry.IsDir && isEditableSiteFile(rel),
				Mode:          entry.Mode,
				Owner:         entry.Owner,
			})
			}
			sort.Slice(entries, func(i int, j int) bool {
				if entries[i].IsDir != entries[j].IsDir {
					return entries[i].IsDir
				}
				return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
			})
			data.SiteBrowserEntries = entries
		}
	}
	selectedFile := strings.TrimSpace(r.URL.Query().Get("file"))
	if data.SiteBrowserSelectedFile != "" && selectedFile == "" {
		// keep the file pre-filled by the action handler (e.g. after
		// save_site_file) so the editor stays open on the same file.
		selectedFile = data.SiteBrowserSelectedFile
	}
	if absFile, relFile, err := resolveSiteBrowserPath(site.RootDirectory, selectedFile); err == nil && relFile != "" {
		data.SiteBrowserSelectedFile = relFile
		if data.SiteBrowserFileContent == "" {
			var content string
			if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": absFile, "max_bytes": 262144}, &content); err == nil {
				data.SiteBrowserFileContent = content
				if strings.Contains(content, "[truncated after ") {
					data.SiteBrowserFileNotice = "Only the first 256 KB is shown."
				}
			}
		}
		data.SiteBrowserFileEditable = isEditableSiteFile(relFile)
		if !data.SiteBrowserFileEditable && data.SiteBrowserFileNotice == "" {
			data.SiteBrowserFileNotice = "This file type is read-only in the panel editor."
		}
	}
	if data.ProjectHasArtisan {
		data.LaravelExtraWritablePaths = firstNonEmpty(data.LaravelExtraWritablePaths, site.LaravelExtraWritablePaths)
		data.LaravelPermissionCommand = buildLaravelPermissionDisplayCommand(site.RootDirectory, site.OwnerLinuxUser, data.LaravelExtraWritablePaths)
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
		}
	}
	if data.RuntimeNodeVersion == "" {
		data.RuntimeNodeVersion = firstNonEmpty(data.PreferredNodeVersion, runtimeStatus.DefaultNodeVersion)
	}
	if data.PM2NodeVersion == "" {
		data.PM2NodeVersion = firstNonEmpty(data.PreferredNodeVersion, runtimeStatus.DefaultNodeVersion, data.RuntimeNodeVersion)
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
	if data.GitCredentialHost == "" {
		data.GitCredentialHost = gitAuthStatus.RepositoryHost
	}
	data.NodeVersionOptions = mergeNodeVersionOptions(
		singleNodeVersionOptions(data.PreferredNodeVersion, data.AutoDeployNodeVersion, data.NpmScriptNodeVersion, data.RuntimeCommandNodeVersion, data.PM2NodeVersion),
		runtimeStatus.InstalledNodeVersions,
	)
	data.InstallNodeVersionOptions = mergeNodeVersionOptions(
		singleNodeVersionOptions(data.RuntimeNodeVersion, data.PreferredNodeVersion),
		runtimeStatus.AvailableNodeVersions,
		runtimeStatus.InstalledNodeVersions,
	)
	a.render(r.Context(), w, r.URL.Path, "site_details.html", data)
}

func (a *App) renderSubdomainDetails(w http.ResponseWriter, r *http.Request, site domain.ManagedSite, subdomain domain.SiteSubdomain, repositoryStatus system.RepositoryStatus, runtimeStatus system.RuntimeStatus, gitAuthStatus system.GitAuthStatus, releases []domain.DeploymentRelease, data TemplateData) {
	data.Title = subdomain.FullDomain + " details"
	data.DatabaseStatus = a.databaseStatus(r.Context())
	data.Metrics = a.metrics.Snapshot()
	data.SelectedSite = site
	data.SelectedSubdomain = subdomain
	data.SubdomainRootBaseDir = strings.TrimSpace(a.cfg.SubdomainRootBaseDir)
	if data.SiteDetailTab == "" {
		data.SiteDetailTab = "overview"
	}
	data.RepositoryStatus = repositoryStatus
	data.RuntimeStatus = runtimeStatus
	data.GitAuthStatus = gitAuthStatus
	data.DeploymentReleases = releases
	data.PreferredNodeVersion = firstNonEmpty(data.PreferredNodeVersion, subdomain.NodeVersion)
	data.PackageScripts = readPackageJSONScripts(subdomain.RootDirectory)
	data.ProjectHasComposer, data.ProjectHasArtisan = a.detectProjectMarkers(r.Context(), subdomain.RootDirectory)
	if data.ProjectHasArtisan {
		data.LaravelExtraWritablePaths = firstNonEmpty(data.LaravelExtraWritablePaths, subdomain.LaravelExtraWritablePaths)
		data.LaravelPermissionCommand = buildLaravelPermissionDisplayCommand(subdomain.RootDirectory, site.OwnerLinuxUser, data.LaravelExtraWritablePaths)
	}
	data.DeployCommandPlaceholder = recommendedDeployCommand(data.ProjectHasComposer, data.ProjectHasArtisan, data.PackageScripts, subdomain.FullDomain)
	data.AutoDeployCommandPlaceholder = data.DeployCommandPlaceholder
	if commands, err := a.store.ListSubdomainRuntimeCommands(r.Context(), subdomain.ID); err == nil {
		data.SubdomainRuntimeCommands = commands
	}
	data.AutoDeployWebhookURL = buildSubdomainAutoDeployWebhookURL(requestExternalBaseURL(r, a.cfg.BaseURL), site.Name, subdomain.ID, firstNonEmpty(data.SubdomainAutoDeploySecret, subdomain.AutoDeploySecret))
	data.AutoDeployWebhookAuthHint = autoDeployWebhookAuthHint()
	data.SubdomainAutoDeployNodeVersion = firstNonEmpty(data.SubdomainAutoDeployNodeVersion, subdomain.AutoDeployNodeVersion, data.PreferredNodeVersion)
	if len(releases) > 0 {
		data.LatestDeploymentRelease = releases[0]
	}
	if entry, err := a.store.GetLatestAuditLogByActionAndTarget(r.Context(), "deploy.webhook", subdomain.FullDomain); err == nil {
		entry.Metadata = summarizeAuditMetadata(entry.Metadata)
		data.LatestWebhookAudit = entry
	}
	if data.SubdomainDirectoryName == "" {
		data.SubdomainDirectoryName = subdomain.Subdomain
	}
	if data.SubdomainRepositoryURL == "" {
		data.SubdomainRepositoryURL = firstNonEmpty(subdomain.RepositoryURL, repositoryStatus.RemoteURL)
	}
	if data.SubdomainBranch == "" {
		data.SubdomainBranch = firstNonEmpty(subdomain.BranchName, repositoryStatus.Branch)
	}
	if data.SubdomainPostDeployCommand == "" {
		data.SubdomainPostDeployCommand = subdomain.PostDeployCommand
	}
	data.SubdomainAutoDeployEnabled = data.SubdomainAutoDeployEnabled || subdomain.AutoDeployEnabled
	data.SubdomainAutoDeployBranch = firstNonEmpty(data.SubdomainAutoDeployBranch, subdomain.AutoDeployBranch, data.SubdomainBranch)
	data.SubdomainAutoDeploySecret = firstNonEmpty(data.SubdomainAutoDeploySecret, subdomain.AutoDeploySecret)
	data.SubdomainAutoDeployCommand = firstNonEmpty(data.SubdomainAutoDeployCommand, subdomain.AutoDeployCommand)
	data.SubdomainAutoDeployNotifyEmail = firstNonEmpty(data.SubdomainAutoDeployNotifyEmail, subdomain.AutoDeployNotifyEmail)
	if data.SubdomainAutoDeployPreset == "" {
		data.SubdomainAutoDeployPreset, data.SubdomainAutoDeployPM2Process = detectAutoDeployPreset(data.SubdomainAutoDeployCommand)
	}
	data.NpmScriptNodeVersion = firstNonEmpty(data.NpmScriptNodeVersion, data.PreferredNodeVersion)
	data.RuntimeNodeVersion = firstNonEmpty(data.RuntimeNodeVersion, data.PreferredNodeVersion, runtimeStatus.DefaultNodeVersion)
	data.RuntimeCommandNodeVersion = firstNonEmpty(data.RuntimeCommandNodeVersion, data.PreferredNodeVersion)
	data.PM2NodeVersion = firstNonEmpty(data.PM2NodeVersion, data.PreferredNodeVersion, runtimeStatus.DefaultNodeVersion)
	data.PM2ProcessName = firstNonEmpty(data.PM2ProcessName, subdomain.FullDomain)
	data.PM2LogLines = firstNonEmpty(data.PM2LogLines, "100")
	data.SubdomainAutoDeployPM2Process = firstNonEmpty(data.SubdomainAutoDeployPM2Process, data.PM2ProcessName)
	data.PM2ScriptPath = firstNonEmpty(data.PM2ScriptPath, "ecosystem.config.cjs")
	data.GitCredentialHost = firstNonEmpty(data.GitCredentialHost, gitAuthStatus.RepositoryHost)
	if data.CronFilter == "" {
		data.CronFilter = "subdomain"
	}
	var allCronJobs []system.CronJob
	if _, err := a.helper.Call(r.Context(), "cron.list", map[string]string{"user": site.OwnerLinuxUser}, &allCronJobs); err == nil {
		filteredJobs := make([]system.CronJob, 0, len(allCronJobs))
		for _, job := range allCronJobs {
			job.NextRunText = describeCronNextRun(job.Schedule, time.Now())
			if data.CronFilter == "all" {
				filteredJobs = append(filteredJobs, job)
				continue
			}
			if job.Managed && job.SiteName == subdomain.FullDomain {
				filteredJobs = append(filteredJobs, job)
			}
		}
		data.CronJobs = filteredJobs
		for _, job := range allCronJobs {
			if data.CronEditID != "" && job.Managed && job.SiteName == subdomain.FullDomain && job.ID == data.CronEditID {
				data.CronSchedule = firstNonEmpty(data.CronSchedule, job.Schedule)
				data.CronCommand = firstNonEmpty(data.CronCommand, job.Command)
				data.CronRunInSiteRoot = job.RunInSiteRoot
			}
			if data.CronLogID != "" && job.ID == data.CronLogID && job.LogPath != "" {
				data.CronLogTitle = firstNonEmpty(job.SiteName, subdomain.FullDomain) + " · " + job.Schedule
				var logContent string
				if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": job.LogPath, "max_bytes": 65536}, &logContent); err == nil {
					data.CronLogContent = logContent
					if data.CronLogNotice == "" && strings.Contains(logContent, "[truncated after ") {
						data.CronLogNotice = "Only the last available 64 KB of the cron log is shown."
					}
				} else if data.CronLogNotice == "" {
					data.CronLogNotice = "Cron log file could not be read yet. The job may not have run yet."
				}
			}
		}
	}
	data.NginxConfigPath = strings.TrimSpace(subdomain.NginxConfigPath)
	if data.NginxConfigPath != "" {
		editor := SiteNginxConfigEditor{TargetType: "subdomain", TargetID: subdomain.ID, Title: subdomain.FullDomain, Domain: subdomain.FullDomain, ConfigPath: data.NginxConfigPath, Notice: data.NginxConfigNotice}
		if isAllowedNginxConfigPath(a.cfg.NginxAvailableDir, editor.ConfigPath) {
			var content string
			if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": editor.ConfigPath, "max_bytes": 1048576}, &content); err == nil {
				editor.Content = content
				if strings.Contains(content, "[truncated after ") {
					editor.Notice = firstNonEmpty(editor.Notice, "Only the first 1 MB of the Nginx config is shown.")
				}
			}
			if data.NginxConfigContent != "" {
				editor.Content = data.NginxConfigContent
			}
			if revisions, err := a.store.ListNginxConfigRevisions(r.Context(), site.ID, subdomain.ID, 8); err == nil {
				editor.Revisions = revisions
			}
		} else {
			editor.Notice = firstNonEmpty(editor.Notice, "Stored Nginx config path is outside the managed Nginx directory and cannot be edited from the panel.")
		}
		data.NginxEditors = append(data.NginxEditors, editor)
	}
	browserPath := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("path")), data.SiteBrowserCurrentPath)
	if absPath, relPath, err := resolveSiteBrowserPath(subdomain.RootDirectory, browserPath); err == nil {
		data.SiteBrowserCurrentPath = relPath
		data.SiteBrowserParentPath = parentRelativePath(relPath)
		var helperEntries []helperSiteFileEntry
		if _, err := a.helper.Call(r.Context(), "files.list_dir", map[string]string{"path": absPath}, &helperEntries); err == nil {
			entries := make([]SiteFileEntry, 0, len(helperEntries))
			for _, entry := range helperEntries {
				rel := filepath.Join(relPath, entry.Name)
			entries = append(entries, SiteFileEntry{
				Name:          entry.Name,
				RelativePath:  rel,
				IsDir:         entry.IsDir,
				Size:          entry.Size,
				IsSymlink:     entry.IsSymlink,
				SymlinkTarget: entry.SymlinkTarget,
				Editable:      !entry.IsDir && isEditableSiteFile(rel),
				Mode:          entry.Mode,
				Owner:         entry.Owner,
			})
			}
			sort.Slice(entries, func(i int, j int) bool {
				if entries[i].IsDir != entries[j].IsDir {
					return entries[i].IsDir
				}
				return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
			})
			data.SiteBrowserEntries = entries
			data.NodeVersionOptions = mergeNodeVersionOptions(
				singleNodeVersionOptions(data.PreferredNodeVersion, data.SubdomainAutoDeployNodeVersion, data.NpmScriptNodeVersion, data.RuntimeCommandNodeVersion, data.PM2NodeVersion),
				runtimeStatus.InstalledNodeVersions,
			)
			data.InstallNodeVersionOptions = mergeNodeVersionOptions(
				singleNodeVersionOptions(data.RuntimeNodeVersion, data.PreferredNodeVersion),
				runtimeStatus.AvailableNodeVersions,
				runtimeStatus.InstalledNodeVersions,
			)
		}
	}
	selectedFile := strings.TrimSpace(r.URL.Query().Get("file"))
	if absFile, relFile, err := resolveSiteBrowserPath(subdomain.RootDirectory, selectedFile); err == nil && relFile != "" {
		data.SiteBrowserSelectedFile = relFile
		var content string
		if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": absFile, "max_bytes": 262144}, &content); err == nil {
			data.SiteBrowserFileContent = content
			if strings.Contains(content, "[truncated after ") {
				data.SiteBrowserFileNotice = "Only the first 256 KB is shown."
			}
		}
	}
	envPath := filepath.Join(subdomain.RootDirectory, ".env")
	var envContent string
	if _, err := a.helper.Call(r.Context(), "files.read_env", map[string]string{"path": envPath}, &envContent); err == nil {
		data.EnvFileContent = envContent
	}
	ecosystemPath := filepath.Join(subdomain.RootDirectory, "ecosystem.config.cjs")
	var ecosystemContent string
	if _, err := a.helper.Call(r.Context(), "files.read_text", map[string]string{"path": ecosystemPath}, &ecosystemContent); err == nil && ecosystemContent != "" {
		if port := extractEcosystemPort(ecosystemContent); port != "" {
			data.EcosystemPort = port
		}
	}
	if data.PreviewSubdomainID == subdomain.ID {
		data.SelectedSubdomain.MovePreviewFrom = data.SubdomainMovePreviewFrom
		data.SelectedSubdomain.MovePreviewTo = data.SubdomainMovePreviewTo
		data.SelectedSubdomain.MovePreviewTargetExists = data.SubdomainMovePreviewTargetExists
		data.SelectedSubdomain.MovePreviewTargetEmpty = data.SubdomainMovePreviewTargetEmpty
		data.SelectedSubdomain.MovePreviewTargetGitRepo = data.SubdomainMovePreviewTargetGitRepo
		data.SelectedSubdomain.MovePreviewTargetState = data.SubdomainMovePreviewTargetState
	}
	a.render(r.Context(), w, r.URL.Path, "subdomain_details.html", data)
}

// extractPortFromUpstream extracts the port number from an upstream URL such as
// "127.0.0.1:3000", "http://127.0.0.1:3000", or "https://example.com:8443".
func extractPortFromUpstream(upstream string) string {
	s := upstream
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return ""
	}
	return port
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
	case errors.Is(err, system.ErrDirtyWorkingTree):
		message = "Deploy blocked because the target repository has local tracked changes. Commit, stash, or discard those changes first. Details: " + err.Error()
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

// fileModePattern matches 3 or 4 digit octal values like "644", "0755",
// "700" etc. Used to validate file_mode form input before passing it
// through the helper.
var fileModePattern = regexp.MustCompile(`^0?[0-7]{3,4}$`)

func validateFileMode(mode string) error {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return nil
	}
	if !fileModePattern.MatchString(mode) {
		return errors.New("file mode must be a 3 or 4 digit octal value like 644 or 0755")
	}
	return nil
}

// editableSiteFileExtensions are file extensions the panel allows
// editing through the Files tab. The list is intentionally narrow
// to text-like formats so we never let an operator overwrite a
// binary asset with a text payload by accident. Extensions are
// matched case-insensitively.
var editableSiteFileExtensions = map[string]struct{}{
	".json":       {},
	".js":         {},
	".mjs":        {},
	".cjs":        {},
	".ts":         {},
	".tsx":        {},
	".jsx":        {},
	".css":        {},
	".scss":       {},
	".sass":       {},
	".html":       {},
	".htm":        {},
	".vue":        {},
	".svelte":     {},
	".php":        {},
	".blade.php":  {},
	".twig":       {},
	".py":         {},
	".rb":         {},
	".go":         {},
	".sh":         {},
	".bash":       {},
	".zsh":        {},
	".env":        {},
	".env.local":  {},
	".env.example": {},
	".env.dist":   {},
	".yml":        {},
	".yaml":       {},
	".toml":       {},
	".ini":        {},
	".conf":       {},
	".cnf":        {},
	".xml":        {},
	".md":         {},
	".markdown":   {},
	".txt":        {},
	".log":        {},
	".gitignore":  {},
	".dockerignore": {},
	".editorconfig": {},
	".lock":       {},
	".sql":        {},
	".csv":        {},
	".tsv":        {},
}

// isEditableSiteFile returns true if the panel should expose the
// file as editable in the Files tab. Hidden git internals and
// non-text extensions are rejected.
func isEditableSiteFile(relPath string) bool {
	if relPath == "" {
		return false
	}
	clean := strings.ToLower(strings.TrimSpace(relPath))
	if strings.HasPrefix(clean, ".git/") || clean == ".git" {
		return false
	}
	base := strings.ToLower(filepath.Base(clean))
	if _, ok := editableSiteFileExtensions["."+base]; ok {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	if ext == "" {
		// dotfiles without extension (.env, .gitignore) handled above
		return false
	}
	if _, ok := editableSiteFileExtensions[ext]; ok {
		return true
	}
	return false
}

func (a *App) buildBackupSpec(site domain.ManagedSite) system.SiteBackupSpec {
	return system.SiteBackupSpec{
		SiteName:        site.Name,
		RootDirectory:   site.RootDirectory,
		OwnerLinuxUser:  site.OwnerLinuxUser,
		DatabaseName:    site.DatabaseName,
		S3Bucket:        site.BackupS3Bucket,
		S3Prefix:        site.BackupS3Prefix,
		Region:          firstNonEmpty(strings.TrimSpace(site.BackupS3Region), "us-east-1"),
		AccessKeyID:     a.cfg.AWSAccessKeyID,
		SecretAccessKey: a.cfg.AWSSecretAccessKey,
		MySQLDefaults:   a.cfg.MySQLAdminDefaultsFile,
	}
}

// runSiteBackup invokes the helper to perform a backup for the given
// site, records a row in site_backups, and updates the site's
// last-run status. It returns the helper output (already trimmed).
func (a *App) runSiteBackup(ctx context.Context, site domain.ManagedSite, triggeredBy string) (string, error) {
	spec := a.buildBackupSpec(site)
	if strings.TrimSpace(spec.AccessKeyID) == "" || strings.TrimSpace(spec.SecretAccessKey) == "" {
		return "", system.ErrAWSCredentialsMissing
	}
	if strings.TrimSpace(spec.S3Bucket) == "" {
		return "", fmt.Errorf("backup s3 bucket is not configured for this site")
	}
	startedAt := time.Now()
	historyID, _ := a.store.CreateSiteBackup(ctx, domain.SiteBackup{
		SiteID:      site.ID,
		SiteName:    site.Name,
		S3Bucket:    spec.S3Bucket,
		S3Prefix:    spec.S3Prefix,
		Status:      "running",
		TriggeredBy: triggeredBy,
		StartedAt:   startedAt,
	})

	var result system.SiteBackupResult
	output, err := a.helper.Call(ctx, "backup.run_site", spec, &result)
	finished := domain.SiteBackup{
		ID:                historyID,
		SiteID:            site.ID,
		SiteName:          site.Name,
		S3Bucket:          result.S3Bucket,
		S3Prefix:          result.S3Prefix,
		FilesKey:          result.FilesKey,
		FilesSizeBytes:    result.FilesSizeBytes,
		DatabaseKey:       result.DatabaseKey,
		DatabaseSizeBytes: result.DatabaseSizeBytes,
		Status:            "success",
		Message:           "Backup completed",
		TriggeredBy:       triggeredBy,
		StartedAt:         startedAt,
	}
	finishStatus := "success"
	finishMessage := "Backup completed"
	if err != nil {
		finished.Status = "failure"
		finished.Message = err.Error()
		finishStatus = "failure"
		finishMessage = err.Error()
	}
	if historyID > 0 {
		_ = a.store.FinishSiteBackup(ctx, finished)
	}
	_ = a.store.UpdateManagedSiteBackupStatus(ctx, site.Name, finishStatus, finishMessage, time.Now().Unix())
	if err == nil {
		a.recordAudit(ctx, "site.backup.run", site.Name, "success", map[string]any{"bucket": result.S3Bucket, "files_key": result.FilesKey, "database_key": result.DatabaseKey, "trigger": triggeredBy})
		// fire-and-forget prune
		retention := site.BackupRetentionCount
		if retention > 0 {
			pruneSpec := struct {
				Spec system.SiteBackupSpec `json:"spec"`
				Keep int                   `json:"keep"`
			}{Spec: spec, Keep: retention}
			_, _ = a.helper.Call(ctx, "backup.prune_site", pruneSpec, nil)
		}
	} else {
		a.recordAudit(ctx, "site.backup.run", site.Name, "failure", map[string]any{"bucket": spec.S3Bucket, "error": err.Error(), "trigger": triggeredBy})
	}
	// Notify by email if SMTP is configured. Pulls the site row back so
	// the email reflects the just-stored "last status" / message rather
	// than the in-memory snapshot we started with.
	if mailSite, mailErr := a.store.GetManagedSiteByName(ctx, site.Name); mailErr == nil {
		now := time.Now()
		finished.FinishedAt = &now
		if emailErr := sendSiteBackupResultEmail(a.cfg, mailSite, finished, triggeredBy); emailErr != nil {
			a.logger.Warn("backup email send failed", "site", site.Name, "error", emailErr)
		}
	}
	return output, err
}

func dnsErrorMessage(err error) string {
	message := err.Error()
	switch {
	case errors.Is(err, system.ErrAWSCredentialsMissing):
		message = "AWS Route 53 credentials are not configured. Add them under Settings first."
	case errors.Is(err, system.ErrInvalidDNSRecordName):
		message = "DNS record name is invalid. Example: api.example.com or @ for the apex."
	case errors.Is(err, system.ErrInvalidDNSRecordType):
		message = "DNS record type is not supported. Allowed: A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TXT."
	case errors.Is(err, system.ErrInvalidDNSRecordTTL):
		message = "TTL must be between 30 and 604800 seconds."
	case errors.Is(err, system.ErrInvalidDNSRecordValue):
		message = "DNS record values are invalid. Provide one value per line, no carriage returns."
	case errors.Is(err, system.ErrInvalidDNSZone):
		message = "Selected hosted zone is invalid. Pick a zone from the dropdown."
	}
	return message
}

func splitDNSRecordValues(raw string) []string {
	parts := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		values = append(values, trimmed)
	}
	return values
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

func shellQuoteForDisplay(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func buildLaravelPermissionDisplayCommand(rootDir string, ownerUser string, extraPathsRaw string) string {
	extraPaths := parseStoredLaravelExtraWritablePaths(extraPathsRaw)
	commands := []string{
		"cd " + shellQuoteForDisplay(rootDir),
		"sudo mkdir -p storage/logs storage/framework/cache storage/framework/sessions storage/framework/views bootstrap/cache",
		"if [ -d vendor/mpdf/mpdf ]; then sudo mkdir -p vendor/mpdf/mpdf/tmp/mpdf; fi",
		"sudo touch storage/logs/laravel.log",
		"sudo chown -R " + ownerUser + ":" + ownerUser + " .",
		"sudo find . -path './.git' -prune -o -type d -exec chmod 755 {} \\;",
		"sudo find . -path './.git' -prune -o -type f -exec chmod 644 {} \\;",
		"sudo chown -R " + ownerUser + ":www-data storage bootstrap/cache",
		"sudo chmod -R ug+rwX storage bootstrap/cache",
		"sudo find storage bootstrap/cache -type d -exec chmod 2775 {} \\;",
		"sudo find storage bootstrap/cache -type f -exec chmod 664 {} \\;",
		"if command -v setfacl >/dev/null 2>&1; then sudo setfacl -R -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage bootstrap/cache && sudo setfacl -R -d -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage bootstrap/cache; fi",
		"sudo mkdir -p storage/logs",
		"sudo touch storage/logs/laravel.log",
		"sudo chown " + ownerUser + ":www-data storage/logs storage/logs/laravel.log",
		"sudo chmod 2775 storage/logs",
		"sudo chmod 664 storage/logs/laravel.log",
		"if command -v setfacl >/dev/null 2>&1; then sudo setfacl -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage/logs && sudo setfacl -d -m u:" + ownerUser + ":rwx -m u:www-data:rwx storage/logs && sudo setfacl -m u:" + ownerUser + ":rw -m u:www-data:rw storage/logs/laravel.log; fi",
		"if find storage -maxdepth 1 -type f -name 'oauth-p*' | grep -q .; then sudo find storage -maxdepth 1 -type f -name 'oauth-p*' -exec chmod 640 {} \\; fi",
		"if [ -d vendor/mpdf/mpdf/tmp ]; then sudo chown -R " + ownerUser + ":www-data vendor/mpdf/mpdf/tmp && sudo chmod -R ug+rwX vendor/mpdf/mpdf/tmp && sudo find vendor/mpdf/mpdf/tmp -type d -exec chmod 2775 {} \\; && sudo find vendor/mpdf/mpdf/tmp -type f -exec chmod 664 {} \\; && if command -v setfacl >/dev/null 2>&1; then sudo setfacl -R -m u:" + ownerUser + ":rwx -m u:www-data:rwx vendor/mpdf/mpdf/tmp && sudo setfacl -R -d -m u:" + ownerUser + ":rwx -m u:www-data:rwx vendor/mpdf/mpdf/tmp; fi; fi",
	}
	for _, path := range extraPaths {
		commands = append(commands,
			"sudo mkdir -p "+shellQuoteForDisplay(path),
			"sudo chown -R "+ownerUser+":www-data "+shellQuoteForDisplay(path),
			"sudo chmod -R ug+rwX "+shellQuoteForDisplay(path),
			"sudo find "+shellQuoteForDisplay(path)+" -type d -exec chmod 2775 {} \\;",
			"sudo find "+shellQuoteForDisplay(path)+" -type f -exec chmod 664 {} \\;",
			"if command -v setfacl >/dev/null 2>&1; then sudo setfacl -R -m u:"+ownerUser+":rwx -m u:www-data:rwx "+shellQuoteForDisplay(path)+" && sudo setfacl -R -d -m u:"+ownerUser+":rwx -m u:www-data:rwx "+shellQuoteForDisplay(path)+"; fi",
		)
	}
	return strings.Join(commands, "\n")
}

func normalizeLaravelExtraWritablePathsInput(raw string) ([]string, string, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	})
	seen := make(map[string]struct{}, len(parts))
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		path := strings.TrimSpace(strings.ReplaceAll(part, "\\", "/"))
		path = strings.TrimPrefix(path, "./")
		if path == "" {
			continue
		}
		cleaned := filepath.Clean(path)
		cleaned = strings.ReplaceAll(cleaned, "\\", "/")
		if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || filepath.IsAbs(cleaned) {
			return nil, "", fmt.Errorf("extra writable paths must stay inside the project root and be relative, for example vendor/mpdf/mpdf/tmp")
		}
		if _, exists := seen[cleaned]; exists {
			continue
		}
		seen[cleaned] = struct{}{}
		normalized = append(normalized, cleaned)
	}
	return normalized, strings.Join(normalized, "\n"), nil
}

func parseStoredLaravelExtraWritablePaths(raw string) []string {
	paths, _, err := normalizeLaravelExtraWritablePathsInput(raw)
	if err != nil {
		return nil
	}
	return paths
}

func (a *App) handleProcesses(w http.ResponseWriter, r *http.Request) {
	users := a.listLinuxUsers()
	selectedUser := strings.TrimSpace(r.URL.Query().Get("run_as_user"))
	selectedAction := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("action")), "list")
	processNames := a.pm2ProcessNames(selectedUser)

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "processes.html", TemplateData{
			Title:                 "Processes",
			DatabaseStatus:        a.databaseStatus(r.Context()),
			Metrics:               a.metrics.Snapshot(),
			LinuxUsers:            users,
			ProcessNames:          processNames,
			ProcessSelectedUser:   selectedUser,
			ProcessSelectedAction: selectedAction,
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
	processNames = a.pm2ProcessNames(strings.TrimSpace(user))

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
			Title:                 "Processes",
			DatabaseStatus:        a.databaseStatus(r.Context()),
			Metrics:               a.metrics.Snapshot(),
			LinuxUsers:            users,
			ProcessNames:          processNames,
			ProcessSelectedUser:   strings.TrimSpace(user),
			ProcessSelectedAction: firstNonEmpty(strings.TrimSpace(action), "list"),
			RequestError:          err.Error(),
			CommandOutput:         output,
		})
		return
	}

	a.recordAudit(r.Context(), "pm2."+action, processName, "success", map[string]any{"run_as_user": user})
	a.render(r.Context(), w, r.URL.Path, "processes.html", TemplateData{
		Title:                 "Processes",
		DatabaseStatus:        a.databaseStatus(r.Context()),
		Metrics:               a.metrics.Snapshot(),
		LinuxUsers:            users,
		ProcessNames:          processNames,
		ProcessSelectedUser:   strings.TrimSpace(user),
		ProcessSelectedAction: firstNonEmpty(strings.TrimSpace(action), "list"),
		SuccessMessage:        message,
		CommandOutput:         output,
	})
}

func (a *App) handleProcessOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user := strings.TrimSpace(r.URL.Query().Get("run_as_user"))
	if user == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "run_as_user is required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"process_names": a.pm2ProcessNames(user)})
}

func (a *App) pm2ProcessNames(user string) []string {
	user = strings.TrimSpace(user)
	if user == "" {
		return nil
	}
	output, err := a.pm2.List(user)
	if err != nil {
		return nil
	}
	return parsePM2ProcessNames(output)
}

func parsePM2ProcessNames(output string) []string {
	seen := map[string]struct{}{}
	names := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.Contains(trimmed, "│") {
			continue
		}
		parts := strings.Split(trimmed, "│")
		if len(parts) < 4 {
			continue
		}
		name := strings.TrimSpace(parts[2])
		if name == "" || strings.EqualFold(name, "name") || strings.HasPrefix(name, "[") {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (a *App) handlePHP(w http.ResponseWriter, r *http.Request) {
	data := a.phpTemplateData(r)

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		data.RequestError = "The submitted PHP form could not be parsed."
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	}

	action := firstNonEmpty(strings.TrimSpace(r.FormValue("php_action")), "switch_version")
	data.PHPExtensionVersion = strings.TrimSpace(r.FormValue("extension_version"))
	selectedExtensions := collectPHPExtensions(r)
	data.PHPExtensionInput = strings.Join(selectedExtensions, ", ")
	data.PHPINISelectedVersion = strings.TrimSpace(r.FormValue("ini_version"))
	data.PHPINIMemoryLimit = strings.TrimSpace(r.FormValue("memory_limit"))
	data.PHPINIUploadMaxFilesize = strings.TrimSpace(r.FormValue("upload_max_filesize"))
	data.PHPINIPostMaxSize = strings.TrimSpace(r.FormValue("post_max_size"))
	data.PHPINIMaxExecutionTime = strings.TrimSpace(r.FormValue("max_execution_time"))

	if serviceAIAction := strings.TrimSpace(r.FormValue("service_ai_action")); serviceAIAction != "" {
		switch serviceAIAction {
		case "analyze":
			result, err := a.requestServiceAIRecommendation(r.Context(), "php", phpAIRecommendationSnapshot(data), false)
			if err != nil {
				data.RequestError = err.Error()
				a.recordAudit(r.Context(), "php.ai.analyze", "php", "failure", map[string]any{"error": err.Error()})
				break
			}
			applyAIRecommendation(&data, result)
			data.SuccessMessage = "OpenAI recommendations loaded successfully."
			a.recordAudit(r.Context(), "php.ai.analyze", "php", "success", nil)
		default:
			data.RequestError = "Invalid OpenAI action."
		}
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	}

	switch action {
	case "install_versions":
		selectedVersions := append([]string{}, r.Form["install_versions"]...)
		output, err := a.php.InstallVersions(selectedVersions)
		if err != nil {
			data.RequestError = phpActionErrorMessage(err)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "php.install_versions", strings.Join(selectedVersions, ","), "failure", map[string]any{"error": err.Error(), "versions": selectedVersions})
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		data = a.phpTemplateData(r)
		data.CommandOutput = output
		data.SuccessMessage = "Selected PHP versions were installed successfully."
		a.recordAudit(r.Context(), "php.install_versions", strings.Join(selectedVersions, ","), "success", map[string]any{"versions": selectedVersions})
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	case "install_extensions":
		output, err := a.php.InstallExtensions(system.PHPExtensionSpec{Version: data.PHPExtensionVersion, Extensions: selectedExtensions})
		if err != nil {
			data.RequestError = phpActionErrorMessage(err)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "php.install_extensions", data.PHPExtensionVersion, "failure", map[string]any{"error": err.Error(), "extensions": selectedExtensions})
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		data = a.phpTemplateData(r)
		data.PHPExtensionVersion = strings.TrimSpace(r.FormValue("extension_version"))
		data.CommandOutput = output
		data.SuccessMessage = "PHP extensions were installed and enabled successfully."
		a.recordAudit(r.Context(), "php.install_extensions", data.PHPExtensionVersion, "success", map[string]any{"extensions": selectedExtensions})
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	case "enable_extensions":
		output, err := a.php.EnableExtensions(system.PHPExtensionSpec{Version: data.PHPExtensionVersion, Extensions: selectedExtensions})
		if err != nil {
			data.RequestError = phpActionErrorMessage(err)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "php.enable_extensions", data.PHPExtensionVersion, "failure", map[string]any{"error": err.Error(), "extensions": selectedExtensions})
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		data = a.phpTemplateData(r)
		data.PHPExtensionVersion = strings.TrimSpace(r.FormValue("extension_version"))
		data.CommandOutput = output
		data.SuccessMessage = "Selected PHP extensions were enabled successfully."
		a.recordAudit(r.Context(), "php.enable_extensions", data.PHPExtensionVersion, "success", map[string]any{"extensions": selectedExtensions})
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	case "disable_extensions":
		output, err := a.php.DisableExtensions(system.PHPExtensionSpec{Version: data.PHPExtensionVersion, Extensions: selectedExtensions})
		if err != nil {
			data.RequestError = phpActionErrorMessage(err)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "php.disable_extensions", data.PHPExtensionVersion, "failure", map[string]any{"error": err.Error(), "extensions": selectedExtensions})
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		data = a.phpTemplateData(r)
		data.PHPExtensionVersion = strings.TrimSpace(r.FormValue("extension_version"))
		data.CommandOutput = output
		data.SuccessMessage = "Selected PHP extensions were disabled successfully."
		data.PHPExtensionInput = strings.Join(selectedExtensions, ", ")
		a.recordAudit(r.Context(), "php.disable_extensions", data.PHPExtensionVersion, "success", map[string]any{"extensions": selectedExtensions})
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	case "update_ini":
		output, err := a.php.UpdateINISettings(system.PHPINIUpdateSpec{
			Version:           data.PHPINISelectedVersion,
			MemoryLimit:       data.PHPINIMemoryLimit,
			UploadMaxFilesize: data.PHPINIUploadMaxFilesize,
			PostMaxSize:       data.PHPINIPostMaxSize,
			MaxExecutionTime:  data.PHPINIMaxExecutionTime,
		})
		if err != nil {
			data.RequestError = phpActionErrorMessage(err)
			data.CommandOutput = output
			a.recordAudit(r.Context(), "php.update_ini", data.PHPINISelectedVersion, "failure", map[string]any{"error": err.Error()})
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		data = a.phpTemplateData(r)
		data.PHPINISelectedVersion = strings.TrimSpace(r.FormValue("ini_version"))
		data.CommandOutput = output
		data.SuccessMessage = "PHP ini settings were updated and php-fpm was restarted successfully."
		a.recordAudit(r.Context(), "php.update_ini", data.PHPINISelectedVersion, "success", map[string]any{})
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	default:
		if a.store == nil {
			data.RequestError = "Managed site storage is not configured yet. Set PANEL_DATABASE_DSN first."
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		siteName := r.FormValue("site_name")
		phpVersion := r.FormValue("php_version")
		site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
		if err != nil {
			a.recordAudit(r.Context(), "php.switch", siteName, "failure", map[string]any{"version": phpVersion, "error": err.Error()})
			data.RequestError = "Managed site could not be found by that name."
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		if err := a.php.SwitchSiteVersion(site.NginxConfigPath, phpVersion); err != nil {
			a.recordAudit(r.Context(), "php.switch", siteName, "failure", map[string]any{"version": phpVersion, "config_path": site.NginxConfigPath, "error": err.Error()})
			data.RequestError = phpActionErrorMessage(err)
			a.render(r.Context(), w, r.URL.Path, "php.html", data)
			return
		}
		_ = a.store.UpdateManagedSitePHPVersion(r.Context(), siteName, phpVersion)
		a.recordAudit(r.Context(), "php.switch", siteName, "success", map[string]any{"version": phpVersion, "config_path": site.NginxConfigPath})
		data = a.phpTemplateData(r)
		data.SuccessMessage = "PHP-FPM version switched successfully."
		data.ResultPath = site.NginxConfigPath
		a.render(r.Context(), w, r.URL.Path, "php.html", data)
		return
	}
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
		if a.logger != nil {
			a.logger.Error("list managed sites", "error", err)
		}
		return nil
	}
	return sites
}

func (a *App) collectDeployNodeVersionOptions(users []system.LinuxUser) []string {
	groups := [][]string{singleNodeVersionOptions("node", "lts/*", "22", "20", "18", "16", "14", "12", "10", "8.17.0")}
	for _, user := range users {
		status, err := a.runtime.Inspect(system.RuntimeInspectSpec{User: user.Username})
		if err != nil {
			continue
		}
		groups = append(groups, status.InstalledNodeVersions, status.AvailableNodeVersions, singleNodeVersionOptions(status.DefaultNodeVersion))
	}
	return mergeNodeVersionOptions(groups...)
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

func (a *App) listPHPInstallableVersions() []string {
	if a.php == nil {
		return nil
	}
	versions, err := a.php.ListInstallableVersions()
	if err != nil {
		return nil
	}
	return versions
}

func filterOutInstalled(candidates, installed []string) []string {
	installedSet := make(map[string]struct{}, len(installed))
	for _, v := range installed {
		installedSet[v] = struct{}{}
	}
	out := make([]string, 0, len(candidates))
	for _, v := range candidates {
		if _, ok := installedSet[v]; !ok {
			out = append(out, v)
		}
	}
	return out
}

func (a *App) listPHPExtensionStatuses(versions []string) []system.PHPExtensionStatus {
	statuses := make([]system.PHPExtensionStatus, 0, len(versions))
	for _, version := range versions {
		status, err := a.php.ListExtensionStatus(version)
		if err != nil {
			continue
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func (a *App) listPHPDiagnostics(versions []string) []system.PHPDiagnostics {
	items := make([]system.PHPDiagnostics, 0, len(versions))
	for _, version := range versions {
		result, err := a.php.Diagnostics(version)
		if err != nil {
			continue
		}
		items = append(items, result)
	}
	return items
}

func (a *App) listPHPINISettings(versions []string) []system.PHPINISettings {
	items := make([]system.PHPINISettings, 0, len(versions))
	for _, version := range versions {
		result, err := a.php.ReadINISettings(version)
		if err != nil {
			continue
		}
		items = append(items, result)
	}
	return items
}

func (a *App) phpTemplateData(r *http.Request) TemplateData {
	versions := a.listPHPVersions()
	statuses := a.listPHPExtensionStatuses(versions)
	encodedStatuses, _ := json.Marshal(statuses)
	iniSettings := a.listPHPINISettings(versions)
	encodedINISettings, _ := json.Marshal(iniSettings)
	return TemplateData{
		Title:                    "PHP",
		DatabaseStatus:           a.databaseStatus(r.Context()),
		Metrics:                  a.metrics.Snapshot(),
		OpenAIConfigured:         a.openAIConfigured(),
		OpenAIModel:              firstNonEmpty(strings.TrimSpace(a.cfg.OpenAIModel), "gpt-4.1-mini"),
		ManagedSites:             a.listManagedSites(r),
		PHPVersions:              versions,
		PHPInstallableVersions:   filterOutInstalled(a.listPHPInstallableVersions(), versions),
		PHPExtensionStatuses:     statuses,
		PHPExtensionStatusesJSON: template.JS(encodedStatuses),
		PHPDiagnostics:           a.listPHPDiagnostics(versions),
		PHPINISettings:           iniSettings,
		PHPINISettingsJSON:       template.JS(encodedINISettings),
		PHPCommonExtensions:      phpCommonExtensions(),
		PHPExtensionPresets:      phpExtensionPresets(),
	}
}

func phpCommonExtensions() []string {
	return []string{"bcmath", "bz2", "curl", "exif", "gd", "gmp", "imagick", "intl", "mbstring", "mysql", "opcache", "pcntl", "pgsql", "redis", "soap", "sockets", "sqlite3", "xml", "zip"}
}

func phpExtensionPresets() []PHPExtensionPresetView {
	return []PHPExtensionPresetView{
		{Name: "Laravel", Description: "Common queue, cache, database, and image stack.", Extensions: []string{"bcmath", "curl", "exif", "gd", "imagick", "intl", "mbstring", "mysql", "opcache", "pcntl", "redis", "xml", "zip"}},
		{Name: "WordPress", Description: "Typical media and MySQL requirements.", Extensions: []string{"curl", "exif", "gd", "imagick", "intl", "mbstring", "mysql", "opcache", "xml", "zip"}},
		{Name: "API", Description: "Lean API profile with cache and JSON/XML helpers.", Extensions: []string{"bcmath", "curl", "intl", "mbstring", "opcache", "redis", "soap", "xml", "zip"}},
	}
}

func collectPHPExtensions(r *http.Request) []string {
	items := make([]string, 0)
	items = append(items, r.Form["php_extensions"]...)
	for _, raw := range strings.FieldsFunc(r.FormValue("php_extension_input"), func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		items = append(items, raw)
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func phpActionErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if errors.Is(err, system.ErrInvalidPHPVersion) {
		return "PHP version must look like 8.1, 8.2, 8.3, or 8.4."
	}
	return message
}

func (a *App) handleRedis(w http.ResponseWriter, r *http.Request) {
	status, inspectErr := a.redis.Inspect()
	data := TemplateData{
		Title:               "Redis",
		DatabaseStatus:      a.databaseStatus(r.Context()),
		Metrics:             a.metrics.Snapshot(),
		RedisStatus:         status,
		OpenAIConfigured:    a.openAIConfigured(),
		OpenAIModel:         firstNonEmpty(strings.TrimSpace(a.cfg.OpenAIModel), "gpt-4.1-mini"),
		RedisUsername:       status.Username,
		RedisPassword:       "",
		RedisEvictionPolicy: firstNonEmpty(status.EvictionPolicy, "noeviction"),
	}
	if status.Port > 0 {
		data.RedisPort = strconv.Itoa(status.Port)
	} else {
		data.RedisPort = "6379"
	}
	data.RedisMaxMemoryMB = strconv.FormatInt(status.MaxMemoryBytes/(1024*1024), 10)
	if inspectErr != nil {
		data.RequestError = "Redis status could not be loaded: " + inspectErr.Error()
	}

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "redis.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		data.RequestError = "The submitted Redis form could not be parsed."
		a.render(r.Context(), w, r.URL.Path, "redis.html", data)
		return
	}

	data.RedisUsername = strings.TrimSpace(r.FormValue("redis_username"))
	if data.RedisUsername == "" {
		data.RedisUsername = status.Username
	}
	if portValue := strings.TrimSpace(r.FormValue("redis_port")); portValue != "" {
		data.RedisPort = portValue
	}
	data.RedisPassword = strings.TrimSpace(r.FormValue("redis_password"))
	if maxMemoryValue := strings.TrimSpace(r.FormValue("redis_max_memory_mb")); maxMemoryValue != "" {
		data.RedisMaxMemoryMB = maxMemoryValue
	}
	if evictionPolicy := strings.TrimSpace(r.FormValue("redis_eviction_policy")); evictionPolicy != "" {
		data.RedisEvictionPolicy = evictionPolicy
	}

	if serviceAIAction := strings.TrimSpace(r.FormValue("service_ai_action")); serviceAIAction != "" {
		switch serviceAIAction {
		case "analyze":
			result, err := a.requestServiceAIRecommendation(r.Context(), "redis", redisAIRecommendationSnapshot(data), false)
			if err != nil {
				data.RequestError = err.Error()
				a.recordAudit(r.Context(), "redis.ai.analyze", status.ServiceName, "failure", map[string]any{"error": err.Error()})
				break
			}
			applyAIRecommendation(&data, result)
			data.SuccessMessage = "OpenAI recommendations loaded successfully."
			a.recordAudit(r.Context(), "redis.ai.analyze", status.ServiceName, "success", nil)
		default:
			data.RequestError = "Invalid OpenAI action."
		}
		a.render(r.Context(), w, r.URL.Path, "redis.html", data)
		return
	}

	action := strings.TrimSpace(r.FormValue("redis_action"))
	switch action {
	case "install":
		output, err := a.redis.Install()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Redis could not be installed: " + err.Error()
			a.recordAudit(r.Context(), "redis.install", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Redis installed and started successfully."
		a.recordAudit(r.Context(), "redis.install", status.ServiceName, "success", nil)
	case "save_config":
		password := data.RedisPassword
		generated := false
		if password == "" {
			secret, err := randomPassword(24)
			if err != nil {
				http.Error(w, "password generation failed", http.StatusInternalServerError)
				return
			}
			password = secret
			generated = true
		}

		port, err := strconv.Atoi(strings.TrimSpace(data.RedisPort))
		if err != nil {
			data.RequestError = "Redis port must be a valid number."
			break
		}
		maxMemoryMB, err := strconv.ParseInt(strings.TrimSpace(data.RedisMaxMemoryMB), 10, 64)
		if err != nil || maxMemoryMB < 0 {
			data.RequestError = "Redis memory limit must be zero or a positive number in MB."
			break
		}

		output, err := a.redis.Configure(system.RedisConfigSpec{
			Username:       data.RedisUsername,
			Password:       password,
			Port:           port,
			MaxMemoryBytes: maxMemoryMB * 1024 * 1024,
			EvictionPolicy: data.RedisEvictionPolicy,
		})
		data.CommandOutput = output
		if err != nil {
			message := err.Error()
			switch {
			case errors.Is(err, system.ErrInvalidRedisUsername):
				message = "Redis username must start with a letter and contain only letters, numbers, dashes, or underscores."
			case errors.Is(err, system.ErrInvalidRedisPassword):
				message = "Redis password cannot be empty or contain spaces."
			case errors.Is(err, system.ErrInvalidRedisPort):
				message = "Redis port must be between 1 and 65535."
			case errors.Is(err, system.ErrInvalidRedisMaxMemory):
				message = "Redis memory limit must be zero or a positive number."
			case errors.Is(err, system.ErrInvalidRedisEvictionPolicy):
				message = "Redis eviction policy is not valid."
			}
			data.RequestError = message
			a.recordAudit(r.Context(), "redis.configure", data.RedisUsername, "failure", map[string]any{"port": port, "max_memory_mb": maxMemoryMB, "eviction_policy": data.RedisEvictionPolicy, "error": err.Error()})
			break
		}
		restartOutput, restartErr := a.redis.Restart()
		if restartOutput != "" {
			if data.CommandOutput != "" {
				data.CommandOutput += "\n\n"
			}
			data.CommandOutput += restartOutput
		}
		if restartErr != nil {
			data.RequestError = "Redis configuration was saved but restart failed: " + restartErr.Error()
			a.recordAudit(r.Context(), "redis.restart", status.ServiceName, "failure", map[string]any{"error": restartErr.Error(), "after": "configure"})
			break
		}
		data.SuccessMessage = "Redis configuration saved and service restarted successfully."
		if generated {
			data.GeneratedSecret = password
		}
		a.recordAudit(r.Context(), "redis.configure", data.RedisUsername, "success", map[string]any{"port": port, "max_memory_mb": maxMemoryMB, "eviction_policy": data.RedisEvictionPolicy})
		a.recordAudit(r.Context(), "redis.restart", status.ServiceName, "success", map[string]any{"after": "configure"})
		data.RedisPassword = ""
	case "start":
		output, err := a.redis.Start()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Redis service could not be started: " + err.Error()
			a.recordAudit(r.Context(), "redis.start", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Redis service started successfully."
		a.recordAudit(r.Context(), "redis.start", status.ServiceName, "success", nil)
	case "stop":
		output, err := a.redis.Stop()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Redis service could not be stopped: " + err.Error()
			a.recordAudit(r.Context(), "redis.stop", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Redis service stopped successfully."
		a.recordAudit(r.Context(), "redis.stop", status.ServiceName, "success", nil)
	case "restart":
		output, err := a.redis.Restart()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Redis service could not be restarted: " + err.Error()
			a.recordAudit(r.Context(), "redis.restart", status.ServiceName, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Redis service restarted successfully."
		a.recordAudit(r.Context(), "redis.restart", status.ServiceName, "success", nil)
	case "test_connection":
		port, err := strconv.Atoi(strings.TrimSpace(data.RedisPort))
		if err != nil {
			data.RequestError = "Redis port must be a valid number."
			break
		}
		output, err := a.redis.TestConnection(system.RedisPingSpec{
			Username: data.RedisUsername,
			Password: data.RedisPassword,
			Port:     port,
		})
		data.CommandOutput = output
		if err != nil {
			message := err.Error()
			switch {
			case errors.Is(err, system.ErrInvalidRedisUsername):
				message = "Redis username must start with a letter and contain only letters, numbers, dashes, or underscores."
			case errors.Is(err, system.ErrInvalidRedisPassword):
				message = "Redis password cannot be empty or contain spaces."
			case errors.Is(err, system.ErrInvalidRedisPort):
				message = "Redis port must be between 1 and 65535."
			}
			data.RequestError = "Redis connection test failed: " + message
			a.recordAudit(r.Context(), "redis.test_connection", data.RedisUsername, "failure", map[string]any{"port": port, "error": err.Error()})
			break
		}
		data.SuccessMessage = "Redis connection test succeeded."
		a.recordAudit(r.Context(), "redis.test_connection", data.RedisUsername, "success", map[string]any{"port": port})
		data.RedisPassword = ""
	default:
		data.RequestError = "Invalid Redis action."
	}

	refreshedStatus, err := a.redis.Inspect()
	if err == nil {
		data.RedisStatus = refreshedStatus
		if data.RedisUsername == "" {
			data.RedisUsername = refreshedStatus.Username
		}
		if strings.TrimSpace(r.FormValue("redis_port")) == "" {
			if refreshedStatus.Port > 0 {
				data.RedisPort = strconv.Itoa(refreshedStatus.Port)
			} else {
				data.RedisPort = "6379"
			}
		}
		if strings.TrimSpace(r.FormValue("redis_max_memory_mb")) == "" {
			data.RedisMaxMemoryMB = strconv.FormatInt(refreshedStatus.MaxMemoryBytes/(1024*1024), 10)
		}
		if strings.TrimSpace(r.FormValue("redis_eviction_policy")) == "" {
			data.RedisEvictionPolicy = firstNonEmpty(refreshedStatus.EvictionPolicy, "noeviction")
		}
	}

	a.render(r.Context(), w, r.URL.Path, "redis.html", data)
}

func (a *App) handleRedisLogs(w http.ResponseWriter, r *http.Request) {
	status, inspectErr := a.redis.Inspect()
	data := TemplateData{
		Title:          "Redis logs",
		DatabaseStatus: a.databaseStatus(r.Context()),
		Metrics:        a.metrics.Snapshot(),
		RedisStatus:    status,
		RedisLogLines:  "200",
	}
	if inspectErr != nil {
		data.RequestError = "Redis status could not be loaded: " + inspectErr.Error()
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.RequestError = "The submitted Redis logs form could not be parsed."
			a.render(r.Context(), w, r.URL.Path, "redis_logs.html", data)
			return
		}
		if lines := strings.TrimSpace(r.FormValue("redis_log_lines")); lines != "" {
			data.RedisLogLines = lines
		}
	}

	lines, err := strconv.Atoi(strings.TrimSpace(data.RedisLogLines))
	if err != nil || lines <= 0 {
		lines = 200
		data.RedisLogLines = "200"
	}
	output, logsErr := a.redis.Logs(lines)
	data.CommandOutput = output
	if logsErr != nil {
		data.RequestError = "Redis logs could not be loaded: " + logsErr.Error()
	} else {
		data.SuccessMessage = "Redis logs loaded successfully."
	}
	a.render(r.Context(), w, r.URL.Path, "redis_logs.html", data)
}

func (a *App) handleSupervisor(w http.ResponseWriter, r *http.Request) {
	data := a.supervisorTemplateData(r)

	if r.Method == http.MethodGet {
		a.render(r.Context(), w, r.URL.Path, "supervisor.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		data.RequestError = "The submitted Supervisor form could not be parsed."
		a.render(r.Context(), w, r.URL.Path, "supervisor.html", data)
		return
	}

	data.SupervisorProgramName = strings.TrimSpace(r.FormValue("supervisor_program_name"))
	data.SupervisorProgramCommand = strings.TrimSpace(r.FormValue("supervisor_program_command"))
	data.SupervisorProgramDirectory = strings.TrimSpace(r.FormValue("supervisor_program_directory"))
	data.SupervisorProgramUser = strings.TrimSpace(r.FormValue("supervisor_program_user"))
	data.SupervisorProgramStdoutLogfile = strings.TrimSpace(r.FormValue("supervisor_program_stdout_logfile"))
	data.SupervisorProgramStderrLogfile = strings.TrimSpace(r.FormValue("supervisor_program_stderr_logfile"))
	data.SupervisorProgramEnvironment = strings.TrimSpace(r.FormValue("supervisor_program_environment"))
	data.SupervisorProgramAutostart = r.FormValue("supervisor_program_autostart") == "1"
	data.SupervisorProgramAutorestart = r.FormValue("supervisor_program_autorestart") == "1"
	if lines := strings.TrimSpace(r.FormValue("supervisor_log_lines")); lines != "" {
		data.SupervisorLogLines = lines
	}
	data.SupervisorLogProgram = strings.TrimSpace(r.FormValue("supervisor_log_program"))

	if serviceAIAction := strings.TrimSpace(r.FormValue("service_ai_action")); serviceAIAction != "" {
		switch serviceAIAction {
		case "analyze":
			result, err := a.requestServiceAIRecommendation(r.Context(), "supervisor", supervisorAIRecommendationSnapshot(data), false)
			if err != nil {
				data.RequestError = err.Error()
				a.recordAudit(r.Context(), "supervisor.ai.analyze", "supervisor", "failure", map[string]any{"error": err.Error()})
				break
			}
			applyAIRecommendation(&data, result)
			data.SuccessMessage = "OpenAI recommendations loaded successfully."
			a.recordAudit(r.Context(), "supervisor.ai.analyze", "supervisor", "success", nil)
		default:
			data.RequestError = "Invalid OpenAI action."
		}
		a.render(r.Context(), w, r.URL.Path, "supervisor.html", data)
		return
	}

	action := strings.TrimSpace(r.FormValue("supervisor_action"))
	switch action {
	case "install":
		output, err := a.supervisor.Install()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Supervisor could not be installed: " + err.Error()
			a.recordAudit(r.Context(), "supervisor.install", "supervisor", "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor installed and started successfully."
		a.recordAudit(r.Context(), "supervisor.install", "supervisor", "success", nil)
	case "start_service":
		output, err := a.supervisor.Start()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Supervisor service could not be started: " + err.Error()
			a.recordAudit(r.Context(), "supervisor.start_service", "supervisor", "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor service started successfully."
		a.recordAudit(r.Context(), "supervisor.start_service", "supervisor", "success", nil)
	case "stop_service":
		output, err := a.supervisor.Stop()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Supervisor service could not be stopped: " + err.Error()
			a.recordAudit(r.Context(), "supervisor.stop_service", "supervisor", "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor service stopped successfully."
		a.recordAudit(r.Context(), "supervisor.stop_service", "supervisor", "success", nil)
	case "restart_service":
		output, err := a.supervisor.Restart()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Supervisor service could not be restarted: " + err.Error()
			a.recordAudit(r.Context(), "supervisor.restart_service", "supervisor", "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor service restarted successfully."
		a.recordAudit(r.Context(), "supervisor.restart_service", "supervisor", "success", nil)
	case "reread":
		output, err := a.supervisor.Reread()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Supervisor reread failed: " + err.Error()
			a.recordAudit(r.Context(), "supervisor.reread", "supervisor", "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor reread completed successfully."
		a.recordAudit(r.Context(), "supervisor.reread", "supervisor", "success", nil)
	case "update":
		output, err := a.supervisor.Update()
		data.CommandOutput = output
		if err != nil {
			data.RequestError = "Supervisor update failed: " + err.Error()
			a.recordAudit(r.Context(), "supervisor.update", "supervisor", "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor update completed successfully."
		a.recordAudit(r.Context(), "supervisor.update", "supervisor", "success", nil)
	case "save_program":
		spec := system.SupervisorProgramSpec{
			Name:          data.SupervisorProgramName,
			Command:       data.SupervisorProgramCommand,
			Directory:     data.SupervisorProgramDirectory,
			User:          data.SupervisorProgramUser,
			AutoStart:     data.SupervisorProgramAutostart,
			AutoRestart:   data.SupervisorProgramAutorestart,
			StdoutLogfile: data.SupervisorProgramStdoutLogfile,
			StderrLogfile: data.SupervisorProgramStderrLogfile,
			Environment:   data.SupervisorProgramEnvironment,
		}
		output, err := a.supervisor.SaveProgram(spec)
		data.CommandOutput = output
		if err != nil {
			data.RequestError = supervisorActionErrorMessage(err)
			a.recordAudit(r.Context(), "supervisor.save_program", spec.Name, "failure", map[string]any{"error": err.Error(), "user": spec.User})
			break
		}
		data.SuccessMessage = "Supervisor program saved successfully."
		a.recordAudit(r.Context(), "supervisor.save_program", spec.Name, "success", map[string]any{"user": spec.User})
	case "remove_program":
		name := strings.TrimSpace(r.FormValue("supervisor_target_program"))
		output, err := a.supervisor.RemoveProgram(system.SupervisorProgramActionSpec{Name: name})
		data.CommandOutput = output
		if err != nil {
			data.RequestError = supervisorActionErrorMessage(err)
			a.recordAudit(r.Context(), "supervisor.remove_program", name, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor program removed successfully."
		a.recordAudit(r.Context(), "supervisor.remove_program", name, "success", nil)
	case "start_program", "stop_program", "restart_program":
		name := strings.TrimSpace(r.FormValue("supervisor_target_program"))
		var (
			output string
			err    error
		)
		spec := system.SupervisorProgramActionSpec{Name: name}
		switch action {
		case "start_program":
			output, err = a.supervisor.StartProgram(spec)
		case "stop_program":
			output, err = a.supervisor.StopProgram(spec)
		default:
			output, err = a.supervisor.RestartProgram(spec)
		}
		data.CommandOutput = output
		if err != nil {
			data.RequestError = supervisorActionErrorMessage(err)
			a.recordAudit(r.Context(), "supervisor."+action, name, "failure", map[string]any{"error": err.Error()})
			break
		}
		data.SuccessMessage = "Supervisor program action completed successfully."
		a.recordAudit(r.Context(), "supervisor."+action, name, "success", nil)
	case "tail_logs":
		lines, err := strconv.Atoi(strings.TrimSpace(data.SupervisorLogLines))
		if err != nil || lines <= 0 {
			data.RequestError = "Supervisor log lines must be a positive number."
			break
		}
		output, err := a.supervisor.TailProgramLogs(system.SupervisorLogSpec{Name: data.SupervisorLogProgram, Lines: lines})
		data.SupervisorLogOutput = output
		if err != nil {
			data.RequestError = "Supervisor logs could not be loaded: " + supervisorActionErrorMessage(err)
			a.recordAudit(r.Context(), "supervisor.tail_logs", data.SupervisorLogProgram, "failure", map[string]any{"error": err.Error(), "lines": lines})
			break
		}
		data.SuccessMessage = "Supervisor logs loaded successfully."
		a.recordAudit(r.Context(), "supervisor.tail_logs", data.SupervisorLogProgram, "success", map[string]any{"lines": lines})
	default:
		data.RequestError = "Invalid Supervisor action."
	}

	refreshed := a.supervisorTemplateData(r)
	refreshed.RequestError = data.RequestError
	refreshed.SuccessMessage = data.SuccessMessage
	refreshed.CommandOutput = data.CommandOutput
	refreshed.SupervisorLogOutput = data.SupervisorLogOutput
	if data.SupervisorProgramName != "" {
		refreshed.SupervisorProgramName = data.SupervisorProgramName
		refreshed.SupervisorProgramCommand = data.SupervisorProgramCommand
		refreshed.SupervisorProgramDirectory = data.SupervisorProgramDirectory
		refreshed.SupervisorProgramUser = data.SupervisorProgramUser
		refreshed.SupervisorProgramStdoutLogfile = data.SupervisorProgramStdoutLogfile
		refreshed.SupervisorProgramStderrLogfile = data.SupervisorProgramStderrLogfile
		refreshed.SupervisorProgramEnvironment = data.SupervisorProgramEnvironment
		refreshed.SupervisorProgramAutostart = data.SupervisorProgramAutostart
		refreshed.SupervisorProgramAutorestart = data.SupervisorProgramAutorestart
	}
	if data.SupervisorLogProgram != "" {
		refreshed.SupervisorLogProgram = data.SupervisorLogProgram
	}
	if data.SupervisorLogLines != "" {
		refreshed.SupervisorLogLines = data.SupervisorLogLines
	}
	a.render(r.Context(), w, r.URL.Path, "supervisor.html", refreshed)
}

func (a *App) supervisorTemplateData(r *http.Request) TemplateData {
	status, inspectErr := a.supervisor.Inspect()
	programs, programsErr := a.supervisor.ListPrograms()
	data := TemplateData{
		Title:                        "Supervisor",
		DatabaseStatus:               a.databaseStatus(r.Context()),
		Metrics:                      a.metrics.Snapshot(),
		OpenAIConfigured:             a.openAIConfigured(),
		OpenAIModel:                  firstNonEmpty(strings.TrimSpace(a.cfg.OpenAIModel), "gpt-4.1-mini"),
		LinuxUsers:                   a.listLinuxUsers(),
		SupervisorStatus:             status,
		SupervisorPrograms:           programs,
		SupervisorProgramAutostart:   true,
		SupervisorProgramAutorestart: true,
		SupervisorLogLines:           "200",
	}
	if inspectErr != nil {
		data.RequestError = "Supervisor status could not be loaded: " + inspectErr.Error()
	} else if programsErr != nil {
		data.RequestError = "Supervisor programs could not be loaded: " + programsErr.Error()
	}
	if editName := strings.TrimSpace(r.URL.Query().Get("edit")); editName != "" {
		for _, program := range programs {
			if program.Name != editName {
				continue
			}
			data.SupervisorProgramName = program.Name
			data.SupervisorProgramCommand = program.Command
			data.SupervisorProgramDirectory = program.Directory
			data.SupervisorProgramUser = program.User
			data.SupervisorProgramStdoutLogfile = program.StdoutLogfile
			data.SupervisorProgramStderrLogfile = program.StderrLogfile
			data.SupervisorProgramEnvironment = program.Environment
			data.SupervisorProgramAutostart = program.AutoStart
			data.SupervisorProgramAutorestart = program.AutoRestart
			break
		}
	}
	if logProgram := strings.TrimSpace(r.URL.Query().Get("logs")); logProgram != "" {
		data.SupervisorLogProgram = logProgram
	}
	return data
}

func supervisorActionErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, system.ErrInvalidSupervisorProgramName):
		return "Supervisor program name may contain only letters, numbers, dots, dashes, and underscores."
	case errors.Is(err, system.ErrInvalidSupervisorCommand):
		return "Supervisor command is required."
	case errors.Is(err, system.ErrInvalidSupervisorDirectory):
		return "Supervisor working directory must be an absolute path."
	case errors.Is(err, system.ErrInvalidSupervisorUser):
		return "Supervisor Linux user is not valid."
	case errors.Is(err, system.ErrInvalidSupervisorLogPath):
		return "Supervisor log paths must be absolute paths."
	case errors.Is(err, system.ErrSupervisorManagedProgramOnly):
		return "Only panel-managed Supervisor programs can be deleted from this page."
	default:
		return err.Error()
	}
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs := []domain.AuditLog{}
	sortField := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("sort")), "created_at")
	sortDirection := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("direction")), "desc")
	outcomeFilter := strings.TrimSpace(r.URL.Query().Get("outcome"))
	if a.store != nil {
		if entries, err := a.store.ListAuditLogsFiltered(r.Context(), 50, sortField, sortDirection, outcomeFilter); err == nil {
			logs = entries
		}
	}
	a.render(r.Context(), w, r.URL.Path, "logs.html", TemplateData{
		Title:              "Logs",
		DatabaseStatus:     a.databaseStatus(r.Context()),
		Metrics:            a.metrics.Snapshot(),
		AuditLogs:          logs,
		AuditSort:          sortField,
		AuditDirection:     sortDirection,
		AuditOutcomeFilter: outcomeFilter,
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

// siteFileActionRequest is the body accepted by the AJAX file endpoint.
type siteFileActionRequest struct {
	SiteName    string `json:"site_name"`
	SubdomainID int64  `json:"subdomain_id"`
	Action      string `json:"action"`
	Path        string `json:"path"`
	Dir         string `json:"dir"`
	Name        string `json:"name"`
	Content     string `json:"content"`
	Mode        string `json:"mode"`
}

// handleSiteFileAction backs the Files tab's AJAX calls. It accepts
// JSON, performs one of save / create / chmod / read, and returns a
// JSON payload. Keeping it on a dedicated endpoint lets the browser
// edit a file without reloading the full site details page.
func (a *App) handleSiteFileAction(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "managed site storage is not configured"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	defer r.Body.Close()
	var req siteFileActionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json payload"})
		return
	}
	siteName := strings.TrimSpace(req.SiteName)
	if siteName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "site_name is required"})
		return
	}
	site, err := a.store.GetManagedSiteByName(r.Context(), siteName)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "managed site could not be found"})
		return
	}

	rootDirectory := site.RootDirectory
	if req.SubdomainID > 0 {
		subdomains, subErr := a.store.ListSiteSubdomains(r.Context(), site.ID)
		if subErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "could not load subdomains"})
			return
		}
		sub, found := findSiteSubdomain(subdomains, req.SubdomainID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "subdomain not found"})
			return
		}
		rootDirectory = sub.RootDirectory
	}

	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "save":
		mode := strings.TrimSpace(req.Mode)
		if err := validateFileMode(mode); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(rootDirectory, req.Path)
		if resolveErr != nil || normalisedRel == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "file path is invalid"})
			return
		}
		if !isEditableSiteFile(normalisedRel) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "this file extension is not editable"})
			return
		}
		if strings.HasSuffix(strings.ToLower(normalisedRel), ".json") {
			trimmed := strings.TrimSpace(req.Content)
			if trimmed != "" && !json.Valid([]byte(trimmed)) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "JSON syntax is invalid"})
				return
			}
		}
		_, callErr := a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":       absPath,
			"content":    req.Content,
			"owner":      site.OwnerLinuxUser,
			"site_root":  rootDirectory,
			"max_bytes":  2 * 1024 * 1024,
			"create_bak": true,
			"mode":       mode,
		}, nil)
		if callErr != nil {
			a.recordAudit(r.Context(), "site.file.save", site.Name, "failure", map[string]any{"path": normalisedRel, "error": callErr.Error()})
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": callErr.Error()})
			return
		}
		a.recordAudit(r.Context(), "site.file.save", site.Name, "success", map[string]any{"path": normalisedRel, "bytes": len(req.Content), "mode": mode, "transport": "ajax"})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": normalisedRel + " saved",
			"file": map[string]any{
				"path": normalisedRel,
				"mode": mode,
				"size": len(req.Content),
			},
		})
	case "create":
		mode := strings.TrimSpace(req.Mode)
		if mode == "" {
			mode = "644"
		}
		if err := validateFileMode(mode); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "file name is required"})
			return
		}
		if strings.ContainsAny(name, `/\:*?"<>|`) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "file name contains invalid characters"})
			return
		}
		rel := name
		if strings.TrimSpace(req.Dir) != "" {
			rel = filepath.Join(strings.TrimSpace(req.Dir), name)
		}
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(rootDirectory, rel)
		if resolveErr != nil || normalisedRel == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "file path is invalid"})
			return
		}
		if !isEditableSiteFile(normalisedRel) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "new files must use a supported text extension"})
			return
		}
		_, callErr := a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":        absPath,
			"content":     req.Content,
			"owner":       site.OwnerLinuxUser,
			"site_root":   rootDirectory,
			"max_bytes":   2 * 1024 * 1024,
			"mode":        mode,
			"create_only": true,
		}, nil)
		if callErr != nil {
			a.recordAudit(r.Context(), "site.file.create", site.Name, "failure", map[string]any{"path": normalisedRel, "error": callErr.Error()})
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": callErr.Error()})
			return
		}
		a.recordAudit(r.Context(), "site.file.create", site.Name, "success", map[string]any{"path": normalisedRel, "mode": mode, "transport": "ajax"})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": normalisedRel + " created",
			"file": map[string]any{
				"path": normalisedRel,
				"mode": mode,
				"size": len(req.Content),
			},
		})
	case "chmod":
		mode := strings.TrimSpace(req.Mode)
		if err := validateFileMode(mode); err != nil || mode == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "file mode is required for chmod"})
			return
		}
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(rootDirectory, req.Path)
		if resolveErr != nil || normalisedRel == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "file path is invalid"})
			return
		}
		var current string
		if _, readErr := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": absPath, "max_bytes": 2 * 1024 * 1024}, &current); readErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "could not read file to chmod: " + readErr.Error()})
			return
		}
		_, callErr := a.helper.Call(r.Context(), "files.write_text", map[string]any{
			"path":      absPath,
			"content":   current,
			"owner":     site.OwnerLinuxUser,
			"site_root": rootDirectory,
			"max_bytes": 2 * 1024 * 1024,
			"mode":      mode,
		}, nil)
		if callErr != nil {
			a.recordAudit(r.Context(), "site.file.chmod", site.Name, "failure", map[string]any{"path": normalisedRel, "mode": mode, "error": callErr.Error()})
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": callErr.Error()})
			return
		}
		a.recordAudit(r.Context(), "site.file.chmod", site.Name, "success", map[string]any{"path": normalisedRel, "mode": mode, "transport": "ajax"})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": normalisedRel + " permissions set to " + mode,
			"file": map[string]any{
				"path": normalisedRel,
				"mode": mode,
			},
		})
	case "read":
		absPath, normalisedRel, resolveErr := resolveSiteBrowserPath(rootDirectory, req.Path)
		if resolveErr != nil || normalisedRel == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "file path is invalid"})
			return
		}
		var content string
		if _, readErr := a.helper.Call(r.Context(), "files.read_text", map[string]any{"path": absPath, "max_bytes": 262144}, &content); readErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": readErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"file": map[string]any{
				"path":     normalisedRel,
				"content":  content,
				"editable": isEditableSiteFile(normalisedRel),
			},
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "unknown action"})
	}
}

func (a *App) handleFirewall(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{Title: "Firewall"}

	fwStatus, statusErr := a.firewall.Status()
	if statusErr == nil {
		data.FirewallStatus = fwStatus
	}

	if r.Method == http.MethodGet {
		if statusErr != nil {
			data.RequestError = "Firewall status could not be loaded: " + statusErr.Error()
		}
		a.render(r.Context(), w, r.URL.Path, "firewall.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		data.RequestError = "The submitted form could not be parsed."
		a.render(r.Context(), w, r.URL.Path, "firewall.html", data)
		return
	}

	action := strings.TrimSpace(r.FormValue("firewall_action"))

	switch action {
	case "enable":
		output, err := a.firewall.Enable()
		if err != nil {
			data.RequestError = "Failed to enable firewall: " + err.Error()
		} else {
			data.SuccessMessage = "Firewall enabled."
			if output != "" {
				data.CommandOutput = output
			}
		}
		a.recordAudit(r.Context(), "firewall.enable", "", firewallOutcome(err), nil)
	case "disable":
		output, err := a.firewall.Disable()
		if err != nil {
			data.RequestError = "Failed to disable firewall: " + err.Error()
		} else {
			data.SuccessMessage = "Firewall disabled."
			if output != "" {
				data.CommandOutput = output
			}
		}
		a.recordAudit(r.Context(), "firewall.disable", "", firewallOutcome(err), nil)
	case "add_rule":
		spec := system.FirewallRuleSpec{
			Port:     strings.TrimSpace(r.FormValue("fw_port")),
			Protocol: strings.TrimSpace(r.FormValue("fw_protocol")),
			Source:   strings.TrimSpace(r.FormValue("fw_source")),
			Action:   strings.TrimSpace(r.FormValue("fw_action")),
		}
		data.FirewallNewPort = spec.Port
		data.FirewallNewProtocol = spec.Protocol
		data.FirewallNewSource = spec.Source
		data.FirewallNewAction = spec.Action
		output, err := a.firewall.AddRule(spec)
		if err != nil {
			data.RequestError = "Failed to add rule: " + err.Error()
		} else {
			data.SuccessMessage = "Rule added."
			if output != "" {
				data.CommandOutput = output
			}
		}
		a.recordAudit(r.Context(), "firewall.add_rule", "", firewallOutcome(err), map[string]any{"port": spec.Port, "protocol": spec.Protocol, "source": spec.Source, "action": spec.Action})
	case "delete_rule":
		numStr := strings.TrimSpace(r.FormValue("fw_rule_number"))
		num, parseErr := strconv.Atoi(numStr)
		if parseErr != nil || num < 1 {
			data.RequestError = "Invalid rule number."
		} else {
			output, err := a.firewall.DeleteRule(num)
			if err != nil {
				data.RequestError = "Failed to delete rule: " + err.Error()
			} else {
				data.SuccessMessage = "Rule deleted."
				if output != "" {
					data.CommandOutput = output
				}
			}
			a.recordAudit(r.Context(), "firewall.delete_rule", "", firewallOutcome(parseErr), map[string]any{"number": num})
		}
	default:
		data.RequestError = "Unknown action."
	}

	// Reload status after mutation
	if refreshed, err := a.firewall.Status(); err == nil {
		data.FirewallStatus = refreshed
	}

	a.render(r.Context(), w, r.URL.Path, "firewall.html", data)
}

func firewallOutcome(err error) string {
	if err == nil {
		return "success"
	}
	return "failure"
}
