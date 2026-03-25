package system

import "errors"

var ErrInvalidRepoURL = errors.New("invalid git repository url")
var ErrInvalidBranch = errors.New("invalid branch name")
var ErrInvalidTargetDirectory = errors.New("invalid target directory")
var ErrInvalidRunAsUser = errors.New("invalid run-as user")
var ErrInvalidNodeVersion = errors.New("invalid node version")
var ErrNVMNotInstalled = errors.New("nvm is not installed")
var ErrInvalidProcessName = errors.New("invalid process name")
var ErrInvalidScriptPath = errors.New("invalid script path")
var ErrInvalidArguments = errors.New("invalid process arguments")
var ErrInvalidGitHost = errors.New("invalid git host")
var ErrInvalidCredentialProtocol = errors.New("invalid credential protocol")
var ErrInvalidCredentialUsername = errors.New("invalid credential username")
var ErrInvalidCredentialPassword = errors.New("invalid credential password")
var ErrInvalidTableName = errors.New("invalid mysql table name")
var ErrInvalidRestorePath = errors.New("invalid mysql restore file path")

type UserManager interface {
	CreateLinuxUser(username string, createHome bool) error
	ListLinuxUsers() ([]LinuxUser, error)
	DeleteLinuxUser(username string, removeHome bool) error
}

type LinuxUser struct {
	Username      string
	UID           int
	HomeDirectory string
	Shell         string
}

type DatabaseManager interface {
	ProvisionDatabase(name string, username string, password string) error
	ListDatabaseAccess() ([]DatabaseAccess, error)
	DeleteDatabaseAccess(name string, username string, host string, dropDatabase bool) error
	RotateUserPassword(username string, host string, password string) error
	RotateAdminPassword(password string) error
	InspectDatabase(spec DatabaseInspectSpec) (DatabaseDetails, error)
	RestoreDatabase(name string, filePath string) (string, error)
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
	Name      string
	Engine    string
	RowCount  int64
	DataSize  int64
	IndexSize int64
}

type DatabaseTablePreview struct {
	Name    string
	Columns []string
	Rows    [][]string
}

type DatabaseDetails struct {
	DatabaseName   string
	SelectedTable  string
	Tables         []DatabaseTableSummary
	Preview        DatabaseTablePreview
	ApproximateSize int64
}

type NginxManager interface {
	ApplySite(spec SiteSpec) (string, error)
	DeleteSite(site SiteRemoval) error
	EnableTLS(request TLSRequest) (string, error)
	ValidateConfig(path string) error
	Reload() error
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
	RepositoryURL     string
	Branch            string
	TargetDirectory   string
	RunAsUser         string
	PostDeployCommand string
}

type RollbackSpec struct {
	TargetDirectory   string
	RunAsUser         string
	ReleaseCommitSHA  string
	PostDeployCommand string
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
	User               string
	HomeDirectory      string
	NVMInstalled       bool
	InstalledNodeVersions []string
	DefaultNodeVersion string
	PM2Installed       bool
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

type RuntimeManager interface {
	Inspect(spec RuntimeInspectSpec) (RuntimeStatus, error)
	InstallNVM(user string) (string, error)
	InstallNode(spec NodeInstallSpec) (string, error)
	InstallPM2(spec PM2InstallSpec) (string, error)
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
}
