//go:build !linux

package system

import "fmt"

type stubRuntimeManager struct{}

func NewRuntimeManager() RuntimeManager {
	return stubRuntimeManager{}
}

func (stubRuntimeManager) Inspect(spec RuntimeInspectSpec) (RuntimeStatus, error) {
	return RuntimeStatus{}, fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func (stubRuntimeManager) InstallNVM(user string) (string, error) {
	return "", fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func (stubRuntimeManager) InstallNode(spec NodeInstallSpec) (string, error) {
	return "", fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func (stubRuntimeManager) InstallPM2(spec PM2InstallSpec) (string, error) {
	return "", fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func (stubRuntimeManager) StartPM2(spec PM2StartSpec) (string, error) {
	return "", fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func (stubRuntimeManager) RunNPMScript(spec NPMScriptSpec) (string, error) {
	return "", fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func (stubRuntimeManager) RunNPMInstall(spec NPMInstallSpec) (string, error) {
	return "", fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}