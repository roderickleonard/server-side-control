//go:build !linux

package system

import "fmt"

type stubPHPManager struct{}

func NewPHPManager() PHPManager {
	return stubPHPManager{}
}

func (stubPHPManager) ListAvailableVersions() ([]string, error) {
	return nil, fmt.Errorf("php-fpm switching is only supported on Ubuntu target hosts")
}

func (stubPHPManager) ListInstallableVersions() ([]string, error) {
	return nil, fmt.Errorf("php management is only supported on Ubuntu target hosts")
}

func (stubPHPManager) InstallVersions(versions []string) (string, error) {
	return "", fmt.Errorf("php management is only supported on Ubuntu target hosts")
}

func (stubPHPManager) ListExtensionStatus(version string) (PHPExtensionStatus, error) {
	return PHPExtensionStatus{}, fmt.Errorf("php management is only supported on Ubuntu target hosts")
}

func (stubPHPManager) InstallExtensions(spec PHPExtensionSpec) (string, error) {
	return "", fmt.Errorf("php management is only supported on Ubuntu target hosts")
}

func (stubPHPManager) EnableExtensions(spec PHPExtensionSpec) (string, error) {
	return "", fmt.Errorf("php management is only supported on Ubuntu target hosts")
}

func (stubPHPManager) SwitchSiteVersion(configPath string, version string) error {
	return fmt.Errorf("php-fpm switching is only supported on Ubuntu target hosts")
}
