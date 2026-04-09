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

func (stubDatabaseManager) InspectDatabase(spec DatabaseInspectSpec) (DatabaseDetails, error) {
	return DatabaseDetails{}, fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) RestoreDatabase(name string, filePath string) (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) InspectService() (MySQLServiceStatus, error) {
	return MySQLServiceStatus{}, fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) ConfigureService(spec MySQLServiceConfigSpec) (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) InstallService() (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) UpgradeService() (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) StartService() (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) StopService() (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) RestartService() (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) ServiceLogs(lines int) (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func (stubDatabaseManager) ExecuteAdminQuery(statement string, maxRows int) (DatabaseQueryResult, error) {
	return DatabaseQueryResult{}, fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func ExecuteDatabaseQuery(adminDefaultsFile string, databaseName string, statement string, maxRows int) (DatabaseQueryResult, error) {
	return DatabaseQueryResult{}, fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}

func ExportDatabase(adminDefaultsFile string, databaseName string, filePath string) (string, error) {
	return "", fmt.Errorf("mysql provisioning is only supported on Ubuntu target hosts")
}
