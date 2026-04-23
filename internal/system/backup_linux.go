//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SiteBackupSpec captures everything the helper needs to take one
// backup of a managed site and upload it to S3.
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

// SiteBackupResult is returned to the caller (helper -> client) so the
// store row can be finalised with sizes and S3 keys.
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

var ErrBackupBucketRequired = errors.New("backup s3 bucket is required")
var ErrBackupRootMissing = errors.New("site root directory is missing")

// niceWrap prepends `nice -n 19 ionice -c 3 ...` to the given argv so
// the command runs at the lowest CPU priority (only scheduled when
// nothing else needs the CPU) and the idle I/O class (only issues
// disk I/O when no other process is doing I/O). Falls back to the
// raw argv if nice/ionice are unavailable on PATH so the backup
// still runs on minimal systems.
func niceWrap(argv ...string) []string {
	if len(argv) == 0 {
		return argv
	}
	wrapped := make([]string, 0, len(argv)+5)
	if _, err := exec.LookPath("nice"); err == nil {
		wrapped = append(wrapped, "nice", "-n", "19")
	}
	if _, err := exec.LookPath("ionice"); err == nil {
		wrapped = append(wrapped, "ionice", "-c", "3")
	}
	wrapped = append(wrapped, argv...)
	if len(wrapped) == len(argv) {
		return argv
	}
	// argv[0] is now the wrapper binary; ensure it's the first arg
	// of exec.CommandContext callers expect.
	return wrapped
}

// RunSiteBackup performs the actual backup: tar+gzip the site root,
// optionally mysqldump+gzip the database, then upload both to S3.
// It writes progress lines to stdout so the helper streamer can tail
// them. Returns the S3 keys and sizes via SiteBackupResult.
func RunSiteBackup(ctx context.Context, spec SiteBackupSpec, stdout io.Writer) (SiteBackupResult, error) {
	if stdout == nil {
		stdout = io.Discard
	}
	result := SiteBackupResult{
		S3Bucket:      strings.TrimSpace(spec.S3Bucket),
		S3Prefix:      strings.TrimSpace(spec.S3Prefix),
		StartedAtUnix: time.Now().Unix(),
	}
	if result.S3Bucket == "" {
		return result, ErrBackupBucketRequired
	}
	root := strings.TrimRight(strings.TrimSpace(spec.RootDirectory), "/")
	if root == "" {
		return result, ErrBackupRootMissing
	}
	if info, statErr := os.Stat(root); statErr != nil || !info.IsDir() {
		return result, fmt.Errorf("site root %s is not a readable directory: %v", root, statErr)
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	prefix := strings.Trim(result.S3Prefix, "/")
	if prefix == "" {
		prefix = "sites/" + spec.SiteName
	}
	folder := prefix + "/" + timestamp

	tempDir, err := os.MkdirTemp("", "ssc-backup-*")
	if err != nil {
		return result, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	s3Client := NewS3Client(spec.AccessKeyID, spec.SecretAccessKey, spec.Region)
	if !s3Client.Configured() {
		return result, ErrAWSCredentialsMissing
	}

	// 1) Tar+gzip the site root. Wrap with nice (CPU priority 19,
	//    lowest) + ionice (idle I/O class) so the backup yields to
	//    real traffic when the server is busy. nice/ionice are part
	//    of coreutils/util-linux and ship by default on Ubuntu.
	filesArchive := filepath.Join(tempDir, "files.tar.gz")
	_, _ = fmt.Fprintf(stdout, "Archiving %s -> %s (nice 19, ionice idle)\n", root, filesArchive)
	tarCtx, cancelTar := context.WithTimeout(ctx, 60*time.Minute)
	tarArgs := niceWrap("tar", "--warning=no-file-changed", "--warning=no-file-removed", "-czf", filesArchive, "-C", root, ".")
	tarCmd := exec.CommandContext(tarCtx, tarArgs[0], tarArgs[1:]...)
	tarOutput, tarErr := tarCmd.CombinedOutput()
	cancelTar()
	if tarErr != nil {
		// tar exit code 1 with "file changed as we read it" is a
		// warning-level outcome; if the archive exists and has size,
		// treat it as success.
		stat, statErr := os.Stat(filesArchive)
		if statErr != nil || stat.Size() == 0 {
			return result, fmt.Errorf("tar site root: %w: %s", tarErr, strings.TrimSpace(string(tarOutput)))
		}
		_, _ = fmt.Fprintln(stdout, "tar reported warnings but archive was created; continuing")
	}
	stat, _ := os.Stat(filesArchive)
	if stat != nil {
		result.FilesSizeBytes = stat.Size()
	}
	result.FilesKey = folder + "/files.tar.gz"
	_, _ = fmt.Fprintf(stdout, "Uploading files archive to s3://%s/%s (%d bytes)\n", result.S3Bucket, result.FilesKey, result.FilesSizeBytes)
	uploadCtx, cancelUpload := context.WithTimeout(ctx, 60*time.Minute)
	if err := s3Client.PutObjectFile(uploadCtx, result.S3Bucket, result.FilesKey, filesArchive, "application/gzip"); err != nil {
		cancelUpload()
		return result, fmt.Errorf("upload files archive: %w", err)
	}
	cancelUpload()

	// 2) mysqldump if a database is assigned.
	databaseName := strings.TrimSpace(spec.DatabaseName)
	if databaseName != "" {
		dbArchive := filepath.Join(tempDir, "db.sql.gz")
		_, _ = fmt.Fprintf(stdout, "Dumping database %s -> %s\n", databaseName, dbArchive)
		defaultsFile := strings.TrimSpace(spec.MySQLDefaults)
		if defaultsFile == "" {
			defaultsFile = "/etc/server-side-control/mysql-admin.cnf"
		}
		// mysqldump with --single-transaction uses MVCC instead of
		// LOCK TABLES on InnoDB, so reads on the live database keep
		// working. --quick streams row-by-row to avoid spiking
		// memory on large tables. nice + ionice keep the process
		// out of the way of real traffic.
		dumpCtx, cancelDump := context.WithTimeout(ctx, 60*time.Minute)
		dumpScript := fmt.Sprintf("mysqldump --defaults-file=%s --single-transaction --quick --routines --triggers --events %s | gzip > %s",
			shellQuote(defaultsFile),
			shellQuote(databaseName),
			shellQuote(dbArchive),
		)
		dumpArgs := niceWrap("bash", "-lc", dumpScript)
		dumpCmd := exec.CommandContext(dumpCtx, dumpArgs[0], dumpArgs[1:]...)
		dumpOutput, dumpErr := dumpCmd.CombinedOutput()
		cancelDump()
		if dumpErr != nil {
			return result, fmt.Errorf("mysqldump: %w: %s", dumpErr, strings.TrimSpace(string(dumpOutput)))
		}
		dbStat, _ := os.Stat(dbArchive)
		if dbStat != nil {
			result.DatabaseSizeBytes = dbStat.Size()
		}
		result.DatabaseKey = folder + "/db.sql.gz"
		_, _ = fmt.Fprintf(stdout, "Uploading database dump to s3://%s/%s (%d bytes)\n", result.S3Bucket, result.DatabaseKey, result.DatabaseSizeBytes)
		uploadDumpCtx, cancelUploadDump := context.WithTimeout(ctx, 60*time.Minute)
		if err := s3Client.PutObjectFile(uploadDumpCtx, result.S3Bucket, result.DatabaseKey, dbArchive, "application/gzip"); err != nil {
			cancelUploadDump()
			return result, fmt.Errorf("upload database archive: %w", err)
		}
		cancelUploadDump()
	} else {
		_, _ = fmt.Fprintln(stdout, "No database assigned to this site; skipping mysqldump.")
	}

	result.FinishedAtUnix = time.Now().Unix()
	_, _ = fmt.Fprintln(stdout, "Backup completed successfully.")
	return result, nil
}

// PruneSiteBackups deletes old timestamp folders under prefix when the
// number of folders exceeds keep. It returns the deleted folders and
// any error encountered (best-effort).
func PruneSiteBackups(ctx context.Context, spec SiteBackupSpec, keep int) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}
	s3Client := NewS3Client(spec.AccessKeyID, spec.SecretAccessKey, spec.Region)
	if !s3Client.Configured() {
		return nil, ErrAWSCredentialsMissing
	}
	prefix := strings.Trim(strings.TrimSpace(spec.S3Prefix), "/")
	if prefix == "" {
		prefix = "sites/" + spec.SiteName
	}
	objects, err := s3Client.ListObjects(ctx, spec.S3Bucket, prefix+"/")
	if err != nil {
		return nil, err
	}
	folders := make(map[string]bool)
	folderOrder := make([]string, 0)
	for _, obj := range objects {
		// keys look like "sites/<site>/<timestamp>/files.tar.gz"
		rel := strings.TrimPrefix(obj.Key, prefix+"/")
		idx := strings.Index(rel, "/")
		if idx <= 0 {
			continue
		}
		folder := prefix + "/" + rel[:idx]
		if !folders[folder] {
			folders[folder] = true
			folderOrder = append(folderOrder, folder)
		}
	}
	// folderOrder follows ListObjects' key-descending sort, so the
	// first `keep` are the newest. Anything past that is pruned.
	if len(folderOrder) <= keep {
		return nil, nil
	}
	deleted := make([]string, 0)
	for _, folder := range folderOrder[keep:] {
		for _, obj := range objects {
			if strings.HasPrefix(obj.Key, folder+"/") {
				_ = s3Client.DeleteObject(ctx, spec.S3Bucket, obj.Key)
			}
		}
		deleted = append(deleted, folder)
	}
	return deleted, nil
}
