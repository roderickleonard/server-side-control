package domain

import (
	"time"

	"github.com/kaganyegin/server-side-control/internal/system"
)

type PanelUser struct {
	ID          int64
	LinuxUser   string
	Role        string
	Enabled     bool
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ManagedSite struct {
	ID                        int64
	Name                      string
	OwnerLinuxUser            string
	DomainName                string
	RootDirectory             string
	LaravelExtraWritablePaths string
	Runtime                   string
	UpstreamURL               string
	PHPVersion                string
	NodeVersion               string
	NginxConfigPath           string
	AWSRoute53ZoneID          string
	AWSRoute53ZoneName        string
	BackupS3Bucket            string
	BackupS3Region            string
	BackupS3Prefix            string
	BackupScheduleHours       int
	BackupRetentionCount      int
	BackupLastRunAt           *time.Time
	BackupLastStatus          string
	BackupLastMessage         string
	DatabaseName              string
	AutoDeployEnabled         bool
	AutoDeployBranch          string
	AutoDeploySecret          string
	AutoDeployCommand         string
	AutoDeployNodeVersion     string
	AutoDeployNotifyEmail     string
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

type Deployment struct {
	ID              int64
	SiteID          int64
	RepositoryURL   string
	BranchName      string
	TargetDirectory string
	RunAsUser       string
	LastStatus      string
	LastOutput      string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type AuditLog struct {
	ID        int64
	Actor     string
	Action    string
	Target    string
	Outcome   string
	Metadata  string
	CreatedAt time.Time
}

type DatabaseBackupToken struct {
	Token          string
	DatabaseName   string
	RecipientEmail string
	FilePath       string
	CreatedBy      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	DownloadedAt   *time.Time
}

type SiteBackup struct {
	ID                int64
	SiteID            int64
	SiteName          string
	S3Bucket          string
	S3Prefix          string
	FilesKey          string
	FilesSizeBytes    int64
	DatabaseKey       string
	DatabaseSizeBytes int64
	Status            string
	Message           string
	TriggeredBy       string
	StartedAt         time.Time
	FinishedAt        *time.Time
}

type SiteRuntimeCommand struct {
	ID          int64     `json:"id"`
	SiteID      int64     `json:"site_id"`
	SubdomainID int64     `json:"subdomain_id"`
	Name        string    `json:"name"`
	CommandBody string    `json:"command_body"`
	NodeVersion string    `json:"node_version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SiteSubdomain struct {
	ID                        int64
	SiteID                    int64
	Subdomain                 string
	FullDomain                string
	LaravelExtraWritablePaths string
	Runtime                   string
	UpstreamURL               string
	PHPVersion                string
	NodeVersion               string
	RepositoryURL             string
	BranchName                string
	GitCredentialProtocol     string
	GitCredentialUsername     string
	PostDeployCommand         string
	AutoDeployEnabled         bool
	AutoDeployBranch          string
	AutoDeploySecret          string
	AutoDeployCommand         string
	AutoDeployNodeVersion     string
	AutoDeployNotifyEmail     string
	RootDirectory             string
	NginxConfigPath           string
	AutoDeployWebhookURL      string
	DeploymentReleases        []DeploymentRelease
	GitAuthStatus             system.GitAuthStatus
	LatestWebhookAudit        AuditLog
	MovePreviewFrom           string
	MovePreviewTo             string
	MovePreviewTargetExists   bool
	MovePreviewTargetEmpty    bool
	MovePreviewTargetGitRepo  bool
	MovePreviewTargetState    string
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

type NginxConfigRevision struct {
	ID          int64
	SiteID      int64
	SubdomainID int64
	ConfigPath  string
	Content     string
	CreatedAt   time.Time
}

type PanelTLSStatus struct {
	Domain        string
	CertificateOK bool
	ExpiresAt     *time.Time
	DaysRemaining int
	Issuer        string
}
