//go:build !linux

package system

import (
	"fmt"
	"io"
)

type stubDeployManager struct{}

func NewDeployManager() DeployManager {
	return stubDeployManager{}
}

func (stubDeployManager) Deploy(spec DeploySpec) (DeployResult, error) {
	return DeployResult{}, fmt.Errorf("git deployment is only supported on Ubuntu target hosts")
}

func (stubDeployManager) Rollback(spec RollbackSpec) (DeployResult, error) {
	return DeployResult{}, fmt.Errorf("git deployment is only supported on Ubuntu target hosts")
}

func (stubDeployManager) Inspect(spec RepositoryInspectSpec) (RepositoryStatus, error) {
	return RepositoryStatus{}, fmt.Errorf("git deployment is only supported on Ubuntu target hosts")
}

func StreamDeploy(spec DeploySpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("git deployment is only supported on Ubuntu target hosts")
}

func StreamGitCommand(spec GitCommandSpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("git deployment is only supported on Ubuntu target hosts")
}
