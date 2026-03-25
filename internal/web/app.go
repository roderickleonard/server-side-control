package web

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
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
	pm2       system.PM2Manager
	php       system.PHPManager
	auth      auth.Authenticator
	sessions  *auth.SessionManager
	router    *http.ServeMux
	staticFS  http.Handler
}

type NavItem struct {
	Label string
	Path  string
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
	GeneratedSecret string
	ResultPath     string
	CommandOutput  string
	CommitSHA      string
	PreviousCommitSHA string
	Metrics        system.Snapshot
	AuditLogs      []domain.AuditLog
	DeploymentReleases []domain.DeploymentRelease
	Alerts         []string
	Nav            []NavItem
	Now            time.Time
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
		pm2:      system.NewHelperPM2Manager(helperClient),
		php:      system.NewHelperPHPManager(helperClient),
		auth:     authenticator,
		sessions: sessions,
		router:   http.NewServeMux(),
		staticFS: http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))),
	}

	app.registerRoutes()
	return app, nil
}

func (a *App) Handler() http.Handler {
	return a.loggingMiddleware(a.sessionMiddleware(a.router))
}

func (a *App) registerRoutes() {
	a.router.Handle("/static/", a.staticFS)
	a.router.HandleFunc("/healthz", a.handleHealthz)
	a.router.HandleFunc("/login", a.handleLogin)
	a.router.HandleFunc("/logout", a.handleLogout)
	a.router.HandleFunc("/", a.handleDashboard)
	a.router.HandleFunc("/users", a.handleUsers)
	a.router.HandleFunc("/databases", a.handleDatabases)
	a.router.HandleFunc("/sites", a.handleSites)
	a.router.HandleFunc("/php", a.handlePHP)
	a.router.HandleFunc("/deploys", a.handleDeploys)
	a.router.HandleFunc("/processes", a.handleProcesses)
	a.router.HandleFunc("/logs", a.handleLogs)
}

func (a *App) nav() []NavItem {
	return []NavItem{
		{Label: "Dashboard", Path: "/"},
		{Label: "Users", Path: "/users"},
		{Label: "Databases", Path: "/databases"},
		{Label: "Sites", Path: "/sites"},
		{Label: "PHP", Path: "/php"},
		{Label: "Deploys", Path: "/deploys"},
		{Label: "Processes", Path: "/processes"},
		{Label: "Logs", Path: "/logs"},
	}
}

func (a *App) render(ctx context.Context, w http.ResponseWriter, currentPath string, page string, data TemplateData) {
	tmpl, err := template.ParseFS(assets, "templates/*.html")
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
