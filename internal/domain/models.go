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
	ID              int64
	Name            string
	OwnerLinuxUser  string
	DomainName      string
	RootDirectory   string
	Runtime         string
	UpstreamURL     string
	PHPVersion      string
	NginxConfigPath string
	DatabaseName    string
	AutoDeployEnabled bool
	AutoDeployBranch string
	AutoDeploySecret string
	AutoDeployCommand string
	AutoDeployNotifyEmail string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Deployment struct {
	ID             int64
	SiteID         int64
	RepositoryURL  string
	BranchName     string
	TargetDirectory string
	RunAsUser      string
	LastStatus     string
	LastOutput     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type AuditLog struct {
	ID          int64
	Actor       string
	Action      string
	Target      string
	Outcome     string
	Metadata    string
	CreatedAt   time.Time
}

type SiteRuntimeCommand struct {
	ID          int64     `json:"id"`
	SiteID      int64     `json:"site_id"`
	Name        string    `json:"name"`
	CommandBody string    `json:"command_body"`
	NodeVersion string    `json:"node_version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SiteSubdomain struct {
	ID              int64
	SiteID          int64
	Subdomain       string
	FullDomain      string
	Runtime         string
	UpstreamURL     string
	PHPVersion      string
	RepositoryURL   string
	BranchName      string
	GitCredentialProtocol string
	GitCredentialUsername string
	PostDeployCommand string
	AutoDeployEnabled bool
	AutoDeployBranch string
	AutoDeploySecret string
	AutoDeployCommand string
	AutoDeployNotifyEmail string
	RootDirectory   string
	NginxConfigPath string
	AutoDeployWebhookURL string
	DeploymentReleases []DeploymentRelease
	GitAuthStatus system.GitAuthStatus
	LatestWebhookAudit AuditLog
	MovePreviewFrom string
	MovePreviewTo string
	MovePreviewTargetExists bool
	MovePreviewTargetEmpty bool
	MovePreviewTargetGitRepo bool
	MovePreviewTargetState string
	CreatedAt       time.Time
	UpdatedAt       time.Time
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
