//go:build !linux

package system

import "fmt"

type stubPM2Manager struct{}

func NewPM2Manager() PM2Manager {
	return stubPM2Manager{}
}

func (stubPM2Manager) List(user string) (string, error) {
	return "", fmt.Errorf("pm2 management is only supported on Ubuntu target hosts")
}

func (stubPM2Manager) Restart(user string, processName string) (string, error) {
	return "", fmt.Errorf("pm2 management is only supported on Ubuntu target hosts")
}

func (stubPM2Manager) Reload(user string, processName string) (string, error) {
	return "", fmt.Errorf("pm2 management is only supported on Ubuntu target hosts")
}

func (stubPM2Manager) Start(user string, processName string) (string, error) {
	return "", fmt.Errorf("pm2 management is only supported on Ubuntu target hosts")
}

func (stubPM2Manager) Stop(user string, processName string) (string, error) {
	return "", fmt.Errorf("pm2 management is only supported on Ubuntu target hosts")
}

func (stubPM2Manager) Logs(user string, processName string, lines int) (string, error) {
	return "", fmt.Errorf("pm2 management is only supported on Ubuntu target hosts")
}
