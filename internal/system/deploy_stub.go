//go:build !linux

package system

import "fmt"

type stubDeployManager struct{}

func NewDeployManager() DeployManager {
	return stubDeployManager{}
}

func (stubDeployManager) Deploy(spec DeploySpec) (DeployResult, error) {
	return DeployResult{}, fmt.Errorf("git deployment is only supported on Ubuntu target hosts")
}
