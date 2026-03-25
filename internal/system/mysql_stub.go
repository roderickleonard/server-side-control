//go:build !linux

package system

import "fmt"

type stubDatabaseManager struct{}

func NewDatabaseManager(adminDefaultsFile string) DatabaseManager {
	return stubDatabaseManager{}
}

func (stubDatabaseManager) ProvisionDatabase(name string, username string, password string) error {
	return fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) RotateAdminPassword(password string) error {
	return fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}