//go:build !linux

package system

import "fmt"

type stubSupervisorManager struct{}

func NewSupervisorManager() SupervisorManager {
	return stubSupervisorManager{}
}

func (stubSupervisorManager) Inspect() (SupervisorStatus, error) {
	return SupervisorStatus{}, fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) Install() (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) Start() (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) Stop() (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) Restart() (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) Reread() (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) Update() (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) ListPrograms() ([]SupervisorProgram, error) {
	return nil, fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) SaveProgram(spec SupervisorProgramSpec) (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) RemoveProgram(spec SupervisorProgramActionSpec) (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) StartProgram(spec SupervisorProgramActionSpec) (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) StopProgram(spec SupervisorProgramActionSpec) (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) RestartProgram(spec SupervisorProgramActionSpec) (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}

func (stubSupervisorManager) TailProgramLogs(spec SupervisorLogSpec) (string, error) {
	return "", fmt.Errorf("supervisor management is only supported on Ubuntu target hosts")
}