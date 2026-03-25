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

func (stubDatabaseManager) ListDatabaseAccess() ([]DatabaseAccess, error) {
	return nil, fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) DeleteDatabaseAccess(name string, username string, host string, dropDatabase bool) error {
	return fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) RotateUserPassword(username string, host string, password string) error {
	return fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) RotateAdminPassword(password string) error {
	return fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}