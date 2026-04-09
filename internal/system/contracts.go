package system

import "errors"

var ErrInvalidRepoURL = errors.New("invalid git repository url")
var ErrInvalidBranch = errors.New("invalid branch name")
var ErrInvalidTargetDirectory = errors.New("invalid target directory")
var ErrInvalidRunAsUser = errors.New("invalid run-as user")
var ErrInvalidUsername = errors.New("invalid linux username")
var ErrUserExists = errors.New("linux user already exists")
var ErrUserNotFound = errors.New("linux user not found")
var ErrProtectedUser = errors.New("linux user is protected")
var ErrInvalidDatabaseName = errors.New("invalid mysql database name")
var ErrInvalidUserName = errors.New("invalid mysql user name")
var ErrInvalidPassword = errors.New("invalid mysql password")
var ErrInvalidSiteName = errors.New("invalid site name")
var ErrInvalidDomain = errors.New("invalid domain")
var ErrInvalidMode = errors.New("invalid site mode")
var ErrInvalidUpstream = errors.New("invalid reverse proxy upstream")
var ErrInvalidRootDirectory = errors.New("invalid root directory")
var ErrInvalidPHPVersion = errors.New("invalid php version")
var ErrInvalidEmail = errors.New("invalid email")
var ErrUnsafeDeletePath = errors.New("unsafe site delete path")
var ErrInvalidRedisUsername = errors.New("invalid redis username")
var ErrInvalidRedisPassword = errors.New("invalid redis password")
var ErrInvalidRedisPort = errors.New("invalid redis port")
var ErrInvalidRedisMaxMemory = errors.New("invalid redis maxmemory")
var ErrInvalidRedisEvictionPolicy = errors.New("invalid redis eviction policy")
var ErrInvalidSupervisorProgramName = errors.New("invalid supervisor program name")
var ErrInvalidSupervisorCommand = errors.New("invalid supervisor command")
var ErrInvalidSupervisorDirectory = errors.New("invalid supervisor directory")
var ErrInvalidSupervisorUser = errors.New("invalid supervisor user")
var ErrInvalidSupervisorLogPath = errors.New("invalid supervisor log path")
var ErrSupervisorManagedProgramOnly = errors.New("only panel-managed supervisor programs can be deleted")
var ErrDirtyWorkingTree = errors.New("repository has local changes")
var ErrInvalidNodeVersion = errors.New("invalid node version")
var ErrNVMNotInstalled = errors.New("nvm is not installed")
var ErrInvalidProcessName = errors.New("invalid process name")
var ErrInvalidScriptPath = errors.New("invalid script path")
var ErrInvalidArguments = errors.New("invalid process arguments")
var ErrInvalidGitHost = errors.New("invalid git host")
var ErrInvalidCredentialProtocol = errors.New("invalid credential protocol")
var ErrInvalidCredentialUsername = errors.New("invalid credential username")
var ErrInvalidCredentialPassword = errors.New("invalid credential password")
var ErrInvalidLinuxPassword = errors.New("invalid linux password")
var ErrInvalidGitCommand = errors.New("invalid git command")
var ErrInvalidTableName = errors.New("invalid mysql table name")
var ErrInvalidRestorePath = errors.New("invalid mysql restore file path")
var ErrInvalidDatabaseQuery = errors.New("invalid mysql query")
var ErrInvalidMySQLMaxConnections = errors.New("invalid mysql max connections")
var ErrInvalidMySQLMaxUserConnections = errors.New("invalid mysql max user connections")
var ErrInvalidMySQLWaitTimeout = errors.New("invalid mysql wait timeout")
var ErrInvalidMySQLInteractiveTimeout = errors.New("invalid mysql interactive timeout")
var ErrInvalidMySQLMaxConnectErrors = errors.New("invalid mysql max connect errors")
var ErrInvalidMySQLThreadCacheSize = errors.New("invalid mysql thread cache size")
var ErrInvalidMySQLTableOpenCache = errors.New("invalid mysql table open cache")
var ErrInvalidMySQLBufferPoolSize = errors.New("invalid mysql InnoDB buffer pool size")
var ErrInvalidMySQLBindAddress = errors.New("invalid mysql bind address")
var ErrInvalidMySQLPort = errors.New("invalid mysql port")
var ErrInvalidMySQLLongQueryTime = errors.New("invalid mysql long query time")
var ErrInvalidMySQLSlowQueryLogPath = errors.New("invalid mysql slow query log path")
var ErrInvalidMySQLLogLines = errors.New("invalid mysql log lines")
var ErrInvalidCronSchedule = errors.New("invalid cron schedule")
var ErrInvalidCronCommand = errors.New("invalid cron command")

type UserManager interface {
	CreateLinuxUser(username string, createHome bool, password string, grantSudo bool) error
	ListLinuxUsers() ([]LinuxUser, error)
	DeleteLinuxUser(username string, removeHome bool) error
	SetLinuxUserPassword(username string, password string) error
	SetLinuxUserSudo(username string, enabled bool) error
	SetLinuxUserPasswordlessSudo(username string, enabled bool) error
}

type LinuxUser struct {
	Username         string
	UID              int
	HomeDirectory    string
	Shell            string
	PasswordSet      bool
	SudoEnabled      bool
	PasswordlessSudo bool
}

type DatabaseManager interface {
	ProvisionDatabase(name string, username string, password string) error
	ListDatabaseAccess() ([]DatabaseAccess, error)
	DeleteDatabaseAccess(name string, username string, host string, dropDatabase bool) error
	RotateUserPassword(username string, host string, password string) error
	RotateAdminPassword(password string) error
	InspectDatabase(spec DatabaseInspectSpec) (DatabaseDetails, error)
	RestoreDatabase(name string, filePath string) (string, error)
	InspectService() (MySQLServiceStatus, error)
	ConfigureService(spec MySQLServiceConfigSpec) (string, error)
	InstallService() (string, error)
	UpgradeService() (string, error)
	StartService() (string, error)
	StopService() (string, error)
	RestartService() (string, error)
	ServiceLogs(lines int) (string, error)
	ExecuteAdminQuery(statement string, maxRows int) (DatabaseQueryResult, error)
}

type DatabaseAccess struct {
	DatabaseName string
	Username     string
	Host         string
}

type DatabaseInspectSpec struct {
	DatabaseName string
	TableName    string
	Limit        int
}

type DatabaseTableSummary struct {
	Name             string
	Engine           string
	RowCount         int64
	DataSize         int64
	IndexSize        int64
	DataSizeDisplay  string
	IndexSizeDisplay string
	TotalSizeDisplay string
}

type DatabaseTablePreview struct {
	Name      string
	Columns   []string
	Rows      [][]string
	Truncated bool
}

type DatabaseDetails struct {
	DatabaseName           string
	SelectedTable          string
	Tables                 []DatabaseTableSummary
	Preview                DatabaseTablePreview
	ApproximateSize        int64
	ApproximateSizeDisplay string
}

type DatabaseQueryResult struct {
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	Message   string     `json:"message"`
	RowCount  int        `json:"row_count"`
	Truncated bool       `json:"truncated"`
}

type MySQLServiceStatus struct {
	Installed                   bool   `json:"installed"`
	Active                      bool   `json:"active"`
	Enabled                     bool   `json:"enabled"`
	ServiceName                 string `json:"service_name"`
	Version                     string `json:"version"`
	ConfigPath                  string `json:"config_path"`
	AdminDefaultsFile           string `json:"admin_defaults_file"`
	CurrentConnections          int    `json:"current_connections"`
	MaxConnections              int    `json:"max_connections"`
	MaxUsedConnections          int    `json:"max_used_connections"`
	MaxUserConnections          int    `json:"max_user_connections"`
	AbortedConnects             int    `json:"aborted_connects"`
	WaitTimeout                 int    `json:"wait_timeout"`
	InteractiveTimeout          int    `json:"interactive_timeout"`
	MaxConnectErrors            int    `json:"max_connect_errors"`
	ThreadCacheSize             int    `json:"thread_cache_size"`
	TableOpenCache              int    `json:"table_open_cache"`
	Port                        int    `json:"port"`
	BindAddress                 string `json:"bind_address"`
	SlowQueryLogEnabled         bool   `json:"slow_query_log_enabled"`
	SlowQueryLogFile            string `json:"slow_query_log_file"`
	LongQueryTimeSeconds        string `json:"long_query_time_seconds"`
	InnodbBufferPoolSizeBytes   int64  `json:"innodb_buffer_pool_size_bytes"`
	InnodbBufferPoolSizeDisplay string `json:"innodb_buffer_pool_size_display"`
}

type MySQLServiceConfigSpec struct {
	MaxConnections         int    `json:"max_connections"`
	MaxUserConnections     int    `json:"max_user_connections"`
	WaitTimeout            int    `json:"wait_timeout"`
	InteractiveTimeout     int    `json:"interactive_timeout"`
	MaxConnectErrors       int    `json:"max_connect_errors"`
	ThreadCacheSize        int    `json:"thread_cache_size"`
	TableOpenCache         int    `json:"table_open_cache"`
	InnodbBufferPoolSizeMB int    `json:"innodb_buffer_pool_size_mb"`
	Port                   int    `json:"port"`
	BindAddress            string `json:"bind_address"`
	SlowQueryLogEnabled    bool   `json:"slow_query_log_enabled"`
	SlowQueryLogFile       string `json:"slow_query_log_file"`
	LongQueryTimeSeconds   string `json:"long_query_time_seconds"`
}

type SiteSpec struct {
	Name           string
	OwnerLinuxUser string
	Domain         string
	Mode           string
	RootDirectory  string
	UpstreamURL    string
	PHPVersion     string
}

type SiteRemoval struct {
	Name          string
	Domain        string
	RootDirectory string
	ConfigPath    string
}

type TLSRequest struct {
	Domain   string
	Email    string
	Redirect bool
}

type NginxManager interface {
	ApplySite(spec SiteSpec) (string, error)
	DeleteSite(site SiteRemoval) error
	EnableTLS(request TLSRequest) (string, error)
	ValidateConfig(path string) error
	Reload() error
}

type PanelProxySpec struct {
	Domain     string `json:"domain"`
	ListenAddr string `json:"listen_addr"`
}

type RepositoryInspectSpec struct {
	TargetDirectory string
	RunAsUser       string
}

type RepositoryStatus struct {
	TargetDirectory string
	RunAsUser       string
	DirectoryExists bool
	IsGitRepo       bool
	RemoteURL       string
	Branch          string
	CurrentCommit   string
}

type DeploySpec struct {
	RepositoryURL         string
	Branch                string
	TargetDirectory       string
	RunAsUser             string
	GitSiteName           string
	PostDeployCommand     string
	PostDeployNodeVersion string
}

type GitCommandSpec struct {
	User             string `json:"user"`
	WorkingDirectory string `json:"working_directory"`
	Command          string `json:"command"`
}

type RollbackSpec struct {
	TargetDirectory       string
	RunAsUser             string
	ReleaseCommitSHA      string
	PostDeployCommand     string
	PostDeployNodeVersion string
}

type DeployResult struct {
	Action            string
	Output            string
	CommitSHA         string
	PreviousCommitSHA string
}

type DeployManager interface {
	Deploy(spec DeploySpec) (DeployResult, error)
	Rollback(spec RollbackSpec) (DeployResult, error)
	Inspect(spec RepositoryInspectSpec) (RepositoryStatus, error)
}

type RuntimeInspectSpec struct {
	User string
}

type RuntimeStatus struct {
	User                  string
	HomeDirectory         string
	NVMInstalled          bool
	InstalledNodeVersions []string
	AvailableNodeVersions []string
	DefaultNodeVersion    string
	PM2Installed          bool
	ComposerInstalled     bool
	ComposerVersion       string
}

type NodeInstallSpec struct {
	User       string
	Version    string
	SetDefault bool
}

type PM2InstallSpec struct {
	User        string
	NodeVersion string
}

type PM2StartSpec struct {
	User             string
	WorkingDirectory string
	ProcessName      string
	ScriptPath       string
	Arguments        string
	NodeVersion      string
}

type NPMScriptSpec struct {
	User             string `json:"user"`
	WorkingDirectory string `json:"working_directory"`
	ScriptName       string `json:"script_name"`
	NodeVersion      string `json:"node_version"`
}

type NPMInstallSpec struct {
	User             string `json:"user"`
	WorkingDirectory string `json:"working_directory"`
	NodeVersion      string `json:"node_version"`
	CI               bool   `json:"ci"`
}

type CustomRuntimeCommandSpec struct {
	User             string `json:"user"`
	WorkingDirectory string `json:"working_directory"`
	CommandBody      string `json:"command_body"`
	NodeVersion      string `json:"node_version"`
}

type ShellCommandSpec struct {
	User             string `json:"user"`
	WorkingDirectory string `json:"working_directory"`
	CommandBody      string `json:"command_body"`
}

type RuntimeManager interface {
	Inspect(spec RuntimeInspectSpec) (RuntimeStatus, error)
	InstallNVM(user string) (string, error)
	InstallNode(spec NodeInstallSpec) (string, error)
	InstallPM2(spec PM2InstallSpec) (string, error)
	InstallComposer() (string, error)
	StartPM2(spec PM2StartSpec) (string, error)
	RunNPMScript(spec NPMScriptSpec) (string, error)
	RunNPMInstall(spec NPMInstallSpec) (string, error)
}

type GitAuthInspectSpec struct {
	User          string
	SiteName      string
	RepositoryURL string
}

type GitAuthStatus struct {
	User                 string
	HomeDirectory        string
	RepositoryProtocol   string
	RepositoryHost       string
	SSHKeyPath           string
	PublicKey            string
	DeployKeyReady       bool
	KnownHostTrusted     bool
	CredentialStorePath  string
	CredentialConfigured bool
}

type GitDeployKeySpec struct {
	User          string
	SiteName      string
	RepositoryURL string
}

type GitHostTrustSpec struct {
	User string
	Host string
}

type GitCredentialSpec struct {
	User     string
	Protocol string
	Host     string
	Username string
	Password string
}

type GitAuthManager interface {
	Inspect(spec GitAuthInspectSpec) (GitAuthStatus, error)
	EnsureDeployKey(spec GitDeployKeySpec) (GitAuthStatus, string, error)
	TrustHost(spec GitHostTrustSpec) (string, error)
	StoreCredential(spec GitCredentialSpec) (string, error)
}

type PM2Manager interface {
	List(user string) (string, error)
	Restart(user string, processName string) (string, error)
	Reload(user string, processName string) (string, error)
	Start(user string, processName string) (string, error)
	Stop(user string, processName string) (string, error)
	Logs(user string, processName string, lines int) (string, error)
}

type PHPManager interface {
	SwitchSiteVersion(configPath string, version string) error
	ListAvailableVersions() ([]string, error)
	ListInstallableVersions() ([]string, error)
	InstallVersions(versions []string) (string, error)
	ListExtensionStatus(version string) (PHPExtensionStatus, error)
	InstallExtensions(spec PHPExtensionSpec) (string, error)
	EnableExtensions(spec PHPExtensionSpec) (string, error)
	DisableExtensions(spec PHPExtensionSpec) (string, error)
	Diagnostics(version string) (PHPDiagnostics, error)
	ReadINISettings(version string) (PHPINISettings, error)
	UpdateINISettings(spec PHPINIUpdateSpec) (string, error)
}

type PHPExtensionSpec struct {
	Version    string   `json:"version"`
	Extensions []string `json:"extensions"`
}

type PHPExtensionStatus struct {
	Version          string   `json:"version"`
	InstalledModules []string `json:"installed_modules"`
	EnabledModules   []string `json:"enabled_modules"`
	AvailableModules []string `json:"available_modules"`
}

type PHPDiagnostics struct {
	Version      string `json:"version"`
	CLIVersion   string `json:"cli_version"`
	InfoSummary  string `json:"info_summary"`
	ModuleOutput string `json:"module_output"`
	FPMStatus    string `json:"fpm_status"`
}

type PHPINISettings struct {
	Version           string `json:"version"`
	MemoryLimit       string `json:"memory_limit"`
	UploadMaxFilesize string `json:"upload_max_filesize"`
	PostMaxSize       string `json:"post_max_size"`
	MaxExecutionTime  string `json:"max_execution_time"`
}

type PHPINIUpdateSpec struct {
	Version           string `json:"version"`
	MemoryLimit       string `json:"memory_limit"`
	UploadMaxFilesize string `json:"upload_max_filesize"`
	PostMaxSize       string `json:"post_max_size"`
	MaxExecutionTime  string `json:"max_execution_time"`
}

type RedisStatus struct {
	Installed      bool   `json:"installed"`
	Active         bool   `json:"active"`
	Enabled        bool   `json:"enabled"`
	ServiceName    string `json:"service_name"`
	Version        string `json:"version"`
	ConfigPath     string `json:"config_path"`
	ACLFilePath    string `json:"acl_file_path"`
	Username       string `json:"username"`
	Port           int    `json:"port"`
	MaxMemoryBytes int64  `json:"max_memory_bytes"`
	EvictionPolicy string `json:"eviction_policy"`
}

type RedisConfigSpec struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	Port           int    `json:"port"`
	MaxMemoryBytes int64  `json:"max_memory_bytes"`
	EvictionPolicy string `json:"eviction_policy"`
}

type RedisPingSpec struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int    `json:"port"`
}

type RedisManager interface {
	Inspect() (RedisStatus, error)
	Install() (string, error)
	Configure(spec RedisConfigSpec) (string, error)
	Start() (string, error)
	Stop() (string, error)
	Restart() (string, error)
	TestConnection(spec RedisPingSpec) (string, error)
	Logs(lines int) (string, error)
}

type SupervisorStatus struct {
	Installed       bool   `json:"installed"`
	Active          bool   `json:"active"`
	Enabled         bool   `json:"enabled"`
	ServiceName     string `json:"service_name"`
	Version         string `json:"version"`
	ConfigDirectory string `json:"config_directory"`
}

type SupervisorProgram struct {
	Name          string `json:"name"`
	Command       string `json:"command"`
	Directory     string `json:"directory"`
	User          string `json:"user"`
	AutoStart     bool   `json:"auto_start"`
	AutoRestart   bool   `json:"auto_restart"`
	StdoutLogfile string `json:"stdout_logfile"`
	StderrLogfile string `json:"stderr_logfile"`
	Environment   string `json:"environment"`
	Status        string `json:"status"`
	ConfigPath    string `json:"config_path"`
	Managed       bool   `json:"managed"`
}

type SupervisorProgramSpec struct {
	Name          string `json:"name"`
	Command       string `json:"command"`
	Directory     string `json:"directory"`
	User          string `json:"user"`
	AutoStart     bool   `json:"auto_start"`
	AutoRestart   bool   `json:"auto_restart"`
	StdoutLogfile string `json:"stdout_logfile"`
	StderrLogfile string `json:"stderr_logfile"`
	Environment   string `json:"environment"`
}

type SupervisorProgramActionSpec struct {
	Name string `json:"name"`
}

type SupervisorLogSpec struct {
	Name  string `json:"name"`
	Lines int    `json:"lines"`
}

type SupervisorManager interface {
	Inspect() (SupervisorStatus, error)
	Install() (string, error)
	Start() (string, error)
	Stop() (string, error)
	Restart() (string, error)
	Reread() (string, error)
	Update() (string, error)
	ListPrograms() ([]SupervisorProgram, error)
	SaveProgram(spec SupervisorProgramSpec) (string, error)
	RemoveProgram(spec SupervisorProgramActionSpec) (string, error)
	StartProgram(spec SupervisorProgramActionSpec) (string, error)
	StopProgram(spec SupervisorProgramActionSpec) (string, error)
	RestartProgram(spec SupervisorProgramActionSpec) (string, error)
	TailProgramLogs(spec SupervisorLogSpec) (string, error)
}

type CronJob struct {
	ID            string `json:"id"`
	Schedule      string `json:"schedule"`
	Command       string `json:"command"`
	RawLine       string `json:"raw_line"`
	SiteName      string `json:"site_name"`
	Managed       bool   `json:"managed"`
	RunInSiteRoot bool   `json:"run_in_site_root"`
	LogPath       string `json:"log_path"`
	NextRunText   string `json:"next_run_text"`
}

type CronJobSpec struct {
	User             string `json:"user"`
	Schedule         string `json:"schedule"`
	Command          string `json:"command"`
	SiteName         string `json:"site_name"`
	WorkingDirectory string `json:"working_directory"`
	RunInSiteRoot    bool   `json:"run_in_site_root"`
}

type CronJobDeleteSpec struct {
	User    string `json:"user"`
	ID      string `json:"id"`
	RawLine string `json:"raw_line"`
}

type CronJobUpdateSpec struct {
	User             string `json:"user"`
	ID               string `json:"id"`
	Schedule         string `json:"schedule"`
	Command          string `json:"command"`
	SiteName         string `json:"site_name"`
	WorkingDirectory string `json:"working_directory"`
	RunInSiteRoot    bool   `json:"run_in_site_root"`
}
