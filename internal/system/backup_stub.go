//go:build !linux

package system

import (
	"context"
	"fmt"
	"io"
)

type SiteBackupSpec struct {
	SiteName        string `json:"site_name"`
	RootDirectory   string `json:"root_directory"`
	OwnerLinuxUser  string `json:"owner_linux_user"`
	DatabaseName    string `json:"database_name"`
	S3Bucket        string `json:"s3_bucket"`
	S3Prefix        string `json:"s3_prefix"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	MySQLDefaults   string `json:"mysql_defaults_file"`
}

type SiteBackupResult struct {
	FilesKey          string `json:"files_key"`
	FilesSizeBytes    int64  `json:"files_size_bytes"`
	DatabaseKey       string `json:"database_key"`
	DatabaseSizeBytes int64  `json:"database_size_bytes"`
	S3Bucket          string `json:"s3_bucket"`
	S3Prefix          string `json:"s3_prefix"`
	StartedAtUnix     int64  `json:"started_at_unix"`
	FinishedAtUnix    int64  `json:"finished_at_unix"`
}

func RunSiteBackup(ctx context.Context, spec SiteBackupSpec, stdout io.Writer) (SiteBackupResult, error) {
	return SiteBackupResult{}, fmt.Errorf("site backups are only supported on Linux target hosts")
}

func PruneSiteBackups(ctx context.Context, spec SiteBackupSpec, keep int) ([]string, error) {
	return nil, fmt.Errorf("site backups are only supported on Linux target hosts")
}
