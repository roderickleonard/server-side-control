//go:build !linux

package system

import "fmt"

type stubUserManager struct{}

func NewUserManager() UserManager {
	return stubUserManager{}
}

func (stubUserManager) CreateLinuxUser(username string, createHome bool, password string, grantSudo bool) error {
	return fmt.Errorf("linux user management is only supported on Ubuntu target hosts")
}

func (stubUserManager) ListLinuxUsers() ([]LinuxUser, error) {
	return nil, fmt.Errorf("linux user management is only supported on Ubuntu target hosts")
}

func (stubUserManager) DeleteLinuxUser(username string, removeHome bool) error {
	return fmt.Errorf("linux user management is only supported on Ubuntu target hosts")
}

func (stubUserManager) SetLinuxUserPassword(username string, password string) error {
	return fmt.Errorf("linux user management is only supported on Ubuntu target hosts")
}

func (stubUserManager) SetLinuxUserSudo(username string, enabled bool) error {
	return fmt.Errorf("linux user management is only supported on Ubuntu target hosts")
}

func (stubUserManager) SetLinuxUserPasswordlessSudo(username string, enabled bool) error {
	return fmt.Errorf("linux user management is only supported on Ubuntu target hosts")
}
