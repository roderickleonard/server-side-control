package web

import (
	"context"
	"embed"
	"html/template"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/kaganyegin/server-side-control/internal/auth"
	"github.com/kaganyegin/server-side-control/internal/config"
	"github.com/kaganyegin/server-side-control/internal/domain"
	"github.com/kaganyegin/server-side-control/internal/store"
	"github.com/kaganyegin/server-side-control/internal/system"
)

//go:embed templates/*.html static/*
var assets embed.FS

type App struct {
	cfg       config.Config
	logger    *slog.Logger
	store     *store.Store
	metrics   system.MetricsCollector
	users     system.UserManager
	databases system.DatabaseManager
	nginx     system.NginxManager
	deploys   system.DeployManager
	runtime   system.RuntimeManager
	gitAuth   system.GitAuthManager
	pm2       system.PM2Manager
	php       system.PHPManager
	redis     system.RedisManager
	supervisor system.SupervisorManager
	helper    *system.HelperClient
	auth      auth.Authenticator
	sessions  *auth.SessionManager
	pendingLogins *auth.PendingLoginManager
	webauthnChallenges *auth.WebAuthnChallengeManager
	loginRateLimiter *auth.LoginRateLimiter
	router    *http.ServeMux
	staticFS  http.Handler
}

type NavItem struct {
	Label string
	Path  string
}

type SiteFileEntry struct {
	Name         string
	RelativePath string
	IsDir        bool
	Size         int64
}

type SiteNginxConfigEditor struct {
	TargetType string
	TargetID   int64
	Title      string
	Domain     string
	ConfigPath string
	Content    string
	Notice     string
	Revisions  []domain.NginxConfigRevision
}

type PHPExtensionPresetView struct {
	Name        string
	Description string
	Extensions  []string
}

type DashboardPM2Entry struct {
	User     string
	ListText string
}

type TemplateData struct {
	Title          string
	CurrentPath    string
	AppName        string
	DatabaseStatus string
	BootstrapUser  string
	CurrentUser    string
	AuthProvider   string
	RequestError   string
	SuccessMessage string
	LoginUsername  string
	LoginStage     string
	LoginRequiresTOTP bool
	LoginPasskeyAvailable bool
	LoginPasskeyAutostart bool
	LoginPasswordVisible bool
	TOTPCode       string
	TOTPEnabled    bool
	TOTPSetupPending bool
	TOTPSetupSecret string
	TOTPProvisioningURI string
	RecoveryCode string
	RecoveryCodes []string
	RecoveryCodesRemaining int
	Passkeys []store.PanelUserPasskey
	PasskeyLabel string
	PasskeyError string
	LinuxUsers     []system.LinuxUser
	DatabaseAccess []system.DatabaseAccess
	DatabaseDetails system.DatabaseDetails
	SelectedDatabaseEntries []system.DatabaseAccess
	ManagedSites   []domain.ManagedSite
	SelectedSite   domain.ManagedSite
	SelectedSubdomain domain.SiteSubdomain
	PHPVersions    []string
	PHPInstallableVersions []string
	PHPExtensionStatuses []system.PHPExtensionStatus
	PHPExtensionStatusesJSON template.JS
	PHPDiagnostics []system.PHPDiagnostics
	PHPINISettings []system.PHPINISettings
	PHPINISettingsJSON template.JS
	PHPExtensionVersion string
	PHPExtensionInput string
	PHPCommonExtensions []string
	PHPExtensionPresets []PHPExtensionPresetView
	PHPINISelectedVersion string
	PHPINIMemoryLimit string
	PHPINIUploadMaxFilesize string
	PHPINIPostMaxSize string
	PHPINIMaxExecutionTime string
	RepositoryStatus system.RepositoryStatus
	RuntimeStatus  system.RuntimeStatus
	GitAuthStatus  system.GitAuthStatus
	SiteDetailTab string
	GitRepositoryURL string
	GitBranch      string
	GitPostDeployCommand string
	DeployNodeVersion string
	RollbackNodeVersion string
	GitCustomCommand string
	SSHWorkingDirectory string
	SSHCommandBody string
	AutoDeployEnabled bool
	AutoDeployBranch string
	AutoDeploySecret string
	AutoDeployCommand string
	AutoDeployNodeVersion string
	AutoDeployNotifyEmail string
	AutoDeployWebhookURL string
	AutoDeployWebhookAuthHint string
	LatestWebhookAudit domain.AuditLog
	LatestDeploymentRelease domain.DeploymentRelease
	RuntimeNodeVersion string
	PreferredNodeVersion string
	PM2NodeVersion string
	PM2ProcessName string
	PM2ScriptPath string
	PM2Arguments string
	PM2LogLines string
	PM2ListOutput string
	PM2LogsOutput string
	GitCredentialHost string
	PanelListenAddr string
	PanelBaseURL string
	PanelServiceName string
	SubdomainRootBaseDir string
	PanelDomain string
	PanelTLSEmail string
	SMTPHost string
	SMTPPort string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom string
	SMTPTo string
	PanelEnvPath string
	PanelProxyConfigPath string
	PanelProxyConfig string
	PanelTLSStatus domain.PanelTLSStatus
	RedisStatus  system.RedisStatus
	RedisUsername string
	RedisPort     string
	RedisPassword string
	RedisMaxMemoryMB string
	RedisEvictionPolicy string
	RedisLogLines string
	SupervisorStatus system.SupervisorStatus
	SupervisorPrograms []system.SupervisorProgram
	SupervisorProgramName string
	SupervisorProgramCommand string
	SupervisorProgramDirectory string
	SupervisorProgramUser string
	SupervisorProgramStdoutLogfile string
	SupervisorProgramStderrLogfile string
	SupervisorProgramEnvironment string
	SupervisorProgramAutostart bool
	SupervisorProgramAutorestart bool
	SupervisorLogLines string
	SupervisorLogProgram string
	SupervisorLogOutput string
	DatabaseRestoreSQL string
	GeneratedSecret string
	ResultPath     string
	CommandOutput  string
	CommitSHA      string
	PreviousCommitSHA string
	Metrics        system.Snapshot
	AuditLogs      []domain.AuditLog
	DeploymentReleases []domain.DeploymentRelease
	PackageScripts []string
	ProjectHasComposer bool
	ProjectHasArtisan bool
	DeployCommandPlaceholder string
	AutoDeployCommandPlaceholder string
	NpmScriptNodeVersion string
	SiteRuntimeCommands []domain.SiteRuntimeCommand
	SubdomainRuntimeCommands []domain.SiteRuntimeCommand
	SiteSubdomains []domain.SiteSubdomain
	SubdomainLabel string
	SubdomainMode string
	SubdomainDirectoryName string
	SubdomainUpstreamURL string
	SubdomainPHPVersion string
	SubdomainRootDirectory string
	SubdomainRepositoryURL string
	SubdomainBranch string
	SubdomainPostDeployCommand string
	SubdomainAutoDeployEnabled bool
	SubdomainAutoDeployBranch string
	SubdomainAutoDeploySecret string
	SubdomainAutoDeployCommand string
	SubdomainAutoDeployNodeVersion string
	SubdomainAutoDeployNotifyEmail string
	SubdomainAutoDeployPreset string
	SubdomainAutoDeployPM2Process string
	PreviewSubdomainID int64
	SubdomainMovePreviewFrom string
	SubdomainMovePreviewTo string
	SubdomainMovePreviewTargetExists bool
	SubdomainMovePreviewTargetEmpty bool
	SubdomainMovePreviewTargetGitRepo bool
	SubdomainMovePreviewTargetState string
	SubdomainDeleteID int64
	SubdomainTLSEmail string
	RuntimeCommandID int64
	RuntimeCommandName string
	RuntimeCommandNodeVersion string
	RuntimeCommandBody string
	NodeVersionOptions []string
	InstallNodeVersionOptions []string
	CronJobs []system.CronJob
	CronSchedule string
	CronCommand string
	CronRunInSiteRoot bool
	CronFilter string
	CronEditID string
	CronLogID string
	CronLogTitle string
	CronLogContent string
	CronLogNotice string
	SiteBrowserCurrentPath string
	SiteBrowserParentPath string
	SiteBrowserSelectedFile string
	SiteBrowserFileContent string
	SiteBrowserFileNotice string
	SiteBrowserEntries []SiteFileEntry
	LaravelPermissionCommand string
	NginxEditors []SiteNginxConfigEditor
	NginxConfigPath string
	NginxConfigContent string
	NginxConfigNotice string
	EnvFileContent string
	EcosystemPort  string
	Alerts         []string
	Nav            []NavItem
	Now            time.Time
	DashboardPM2Entries []DashboardPM2Entry
	DashboardMemPct     int
	DashboardDiskPct    int
}

func New(cfg config.Config, logger *slog.Logger, dataStore *store.Store, metrics system.MetricsCollector, authenticator auth.Authenticator, sessions *auth.SessionManager) (*App, error) {
	staticRoot, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	helperClient := system.NewHelperClient(cfg.HelperBinary)

	app := &App{
		cfg:      cfg,
		logger:   logger,
		store:    dataStore,
		metrics:  metrics,
		users:    system.NewHelperUserManager(helperClient),
		databases: system.NewHelperDatabaseManager(helperClient),
		nginx:    system.NewHelperNginxManager(helperClient),
		deploys:  system.NewHelperDeployManager(helperClient),
		runtime:  system.NewHelperRuntimeManager(helperClient),
		gitAuth:  system.NewHelperGitAuthManager(helperClient),
		pm2:      system.NewHelperPM2Manager(helperClient),
		php:      system.NewHelperPHPManager(helperClient),
		redis:    system.NewHelperRedisManager(helperClient),
		supervisor: system.NewHelperSupervisorManager(helperClient),
		helper:   helperClient,
		auth:     authenticator,
		sessions: sessions,
		pendingLogins: auth.NewPendingLoginManager(5 * time.Minute),
		webauthnChallenges: auth.NewWebAuthnChallengeManager(5 * time.Minute),
		loginRateLimiter: auth.NewLoginRateLimiter(10, 10*time.Minute, 15*time.Minute),
		router:   http.NewServeMux(),
		staticFS: http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))),
	}

	app.registerRoutes()
	return app, nil
}

func (a *App) Handler() http.Handler {
	return a.loggingMiddleware(a.securityHeadersMiddleware(a.sessionMiddleware(a.router)))
}

func (a *App) registerRoutes() {
	a.router.Handle("/static/", a.staticFS)
	a.router.HandleFunc("/healthz", a.handleHealthz)
	a.router.HandleFunc("/login", a.handleLogin)
	a.router.HandleFunc("/login/passkey/begin", a.handlePasskeyLoginBegin)
	a.router.HandleFunc("/login/passkey/finish", a.handlePasskeyLoginFinish)
	a.router.HandleFunc("/logout", a.handleLogout)
	a.router.HandleFunc("/", a.handleDashboard)
	a.router.HandleFunc("/users", a.handleUsers)
	a.router.HandleFunc("/users/stream", a.handleUsersStream)
	a.router.HandleFunc("/databases", a.handleDatabases)
	a.router.HandleFunc("/databases/details", a.handleDatabaseDetails)
	a.router.HandleFunc("/databases/details/stream", a.handleDatabaseDetailsStream)
	a.router.HandleFunc("/sites", a.handleSites)
	a.router.HandleFunc("/sites/stream", a.handleSitesStream)
	a.router.HandleFunc("/sites/details", a.handleSiteDetails)
	a.router.HandleFunc("/sites/subdomains/details", a.handleSubdomainDetails)
	a.router.HandleFunc("/sites/details/runtime-stream", a.handleSiteRuntimeStream)
	a.router.HandleFunc("/sites/details/action-stream", a.handleSiteActionStream)
	a.router.HandleFunc("/sites/details/terminal-ws", a.handleSiteTerminalWS)
	a.router.HandleFunc("/webhooks/site-deploy", a.handleSiteDeployWebhook)
	a.router.HandleFunc("/settings", a.handleSettings)
	a.router.HandleFunc("/settings/stream", a.handleSettingsStream)
	a.router.HandleFunc("/settings/passkeys/begin", a.handlePasskeyRegisterBegin)
	a.router.HandleFunc("/settings/passkeys/finish", a.handlePasskeyRegisterFinish)
	a.router.HandleFunc("/php", a.handlePHP)
	a.router.HandleFunc("/php/stream", a.handlePHPStream)
	a.router.HandleFunc("/redis", a.handleRedis)
	a.router.HandleFunc("/redis/stream", a.handleRedisStream)
	a.router.HandleFunc("/redis/logs", a.handleRedisLogs)
	a.router.HandleFunc("/supervisor", a.handleSupervisor)
	a.router.HandleFunc("/supervisor/stream", a.handleSupervisorStream)
	a.router.HandleFunc("/deploys", a.handleDeploys)
	a.router.HandleFunc("/deploys/stream", a.handleDeploysStream)
	a.router.HandleFunc("/processes", a.handleProcesses)
	a.router.HandleFunc("/processes/stream", a.handleProcessesStream)
	a.router.HandleFunc("/logs", a.handleLogs)
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *App) nav() []NavItem {
	return []NavItem{
		{Label: "Dashboard", Path: "/"},
		{Label: "Users", Path: "/users"},
		{Label: "Databases", Path: "/databases"},
		{Label: "Sites", Path: "/sites"},
		{Label: "Settings", Path: "/settings"},
		{Label: "PHP", Path: "/php"},
		{Label: "Redis", Path: "/redis"},
		{Label: "Supervisor", Path: "/supervisor"},
		{Label: "Deploys", Path: "/deploys"},
		{Label: "Processes", Path: "/processes"},
		{Label: "Logs", Path: "/logs"},
	}
}

func (a *App) render(ctx context.Context, w http.ResponseWriter, currentPath string, page string, data TemplateData) {
	if currentPath != "/login" {
		if _, ok := auth.IdentityFromContext(ctx); !ok {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
	}

	tmpl, err := template.ParseFS(assets, templateFilesForPage(page)...)
	if err != nil {
		a.logger.Error("parse template", "page", page, "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	data.CurrentPath = currentPath
	data.AppName = a.cfg.AppName
	data.BootstrapUser = a.cfg.BootstrapUser
	data.Nav = a.nav()
	data.Now = time.Now()
	if identity, ok := auth.IdentityFromContext(ctx); ok {
		data.CurrentUser = identity.DisplayName
		data.AuthProvider = identity.AuthProvider
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		a.logger.Error("render template", "page", page, "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func templateFilesForPage(page string) []string {
	files := []string{"templates/layout.html", "templates/" + page}

	switch page {
	case "sites.html":
		files = append(files, "templates/site_tls.html")
	case "deploys.html":
		files = append(files, "templates/deploy_history.html")
	case "site_details.html":
		files = append(files, "templates/deploy_history.html")
	case "subdomain_details.html":
		files = append(files, "templates/deploy_history.html")
	}

	return files
}

func (a *App) databaseStatus(ctx context.Context) string {
	if a.store == nil {
		return "Not configured"
	}

	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := a.store.Ping(pingCtx); err != nil {
		return "Unreachable"
	}
	return "Connected"
}
