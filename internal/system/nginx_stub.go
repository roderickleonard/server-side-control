//go:build !linux

package system

import "fmt"

type stubNginxManager struct{}

func NewNginxManager(availableDir string, enabledDir string, binary string, certbot string) NginxManager {
	return stubNginxManager{}
}

func (stubNginxManager) ApplySite(spec SiteSpec) (string, error) {
	return "", fmt.Errorf("nginx management is only supported on Ubuntu target hosts")
}

func (stubNginxManager) DeleteSite(site SiteRemoval) error {
	return fmt.Errorf("nginx management is only supported on Ubuntu target hosts")
}

func (stubNginxManager) EnableTLS(request TLSRequest) (string, error) {
	return "", fmt.Errorf("nginx management is only supported on Ubuntu target hosts")
}

func (stubNginxManager) ValidateConfig(path string) error {
	return fmt.Errorf("nginx management is only supported on Ubuntu target hosts")
}

func (stubNginxManager) Reload() error {
	return fmt.Errorf("nginx management is only supported on Ubuntu target hosts")
}
