package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"path/filepath"
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
		homeDirectory := filepath.Clean(user.HomeDirectory)
		if strings.HasPrefix(homeDirectory, "/var/www/") {
			return filepath.Join(homeDirectory, siteName), nil
		}
		return filepath.Join(homeDirectory, "var", "www", siteName), nil
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
