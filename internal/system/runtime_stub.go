//go:build !linux

package system

import (
	"fmt"
	"io"
)

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

func StreamNPMScript(spec NPMScriptSpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func StreamNPMInstall(spec NPMInstallSpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func StreamCustomRuntimeCommand(spec CustomRuntimeCommandSpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}

func StreamShellCommand(spec ShellCommandSpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("runtime management is only supported on Ubuntu target hosts")
}