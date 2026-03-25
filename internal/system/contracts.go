package system

type UserManager interface {
	CreateLinuxUser(username string, createHome bool) error
}

type DatabaseManager interface {
	ProvisionDatabase(name string, username string, password string) error
	RotateAdminPassword(password string) error
}

type NginxManager interface {
	ApplySite(spec SiteSpec) (string, error)
	EnableTLS(request TLSRequest) (string, error)
	ValidateConfig(path string) error
	Reload() error
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
}
