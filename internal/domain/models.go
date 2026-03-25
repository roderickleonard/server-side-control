package domain

import "time"

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
