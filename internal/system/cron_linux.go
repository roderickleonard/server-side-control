//go:build linux

package system

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const cronManagedPrefix = "# SSC:"

type managedCronMetadata struct {
	ID   string `json:"id"`
	Site string `json:"site"`
	Root string `json:"root"`
	Cmd  string `json:"cmd"`
	Log  string `json:"log"`
	CWD  string `json:"cwd,omitempty"`
}

func ListCronJobs(user string) ([]CronJob, error) {
	user = strings.TrimSpace(user)
	if !usernamePattern.MatchString(user) {
		return nil, ErrInvalidUsername
	}
	content, err := readUserCrontab(user)
	if err != nil {
		return nil, err
	}
	return parseCronJobs(content), nil
}

func CreateCronJob(spec CronJobSpec) (string, error) {
	spec.User = strings.TrimSpace(spec.User)
	spec.Schedule = strings.TrimSpace(spec.Schedule)
	spec.Command = strings.TrimSpace(spec.Command)
	spec.SiteName = strings.TrimSpace(spec.SiteName)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	if !usernamePattern.MatchString(spec.User) {
		return "", ErrInvalidUsername
	}
	if !isValidCronSchedule(spec.Schedule) {
		return "", ErrInvalidCronSchedule
	}
	if spec.Command == "" {
		return "", ErrInvalidCronCommand
	}
	if spec.RunInSiteRoot {
		if !filepath.IsAbs(spec.WorkingDirectory) {
			return "", ErrInvalidTargetDirectory
		}
	}
	id, err := randomCronID()
	if err != nil {
		return "", err
	}
	logPath, err := resolveCronLogPath(spec.User, spec.SiteName, id)
	if err != nil {
		return "", err
	}
	if err := ensureCronLogWritable(spec.User, logPath); err != nil {
		return "", err
	}
	current, err := readUserCrontab(spec.User)
	if err != nil {
		return "", err
	}
	line := buildManagedCronLine(id, logPath, spec)
	updated := appendCronLine(current, line)
	if err := writeUserCrontab(spec.User, updated); err != nil {
		return "", err
	}
	return line, nil
}

func UpdateCronJob(spec CronJobUpdateSpec) (string, error) {
	spec.User = strings.TrimSpace(spec.User)
	spec.ID = strings.TrimSpace(spec.ID)
	spec.Schedule = strings.TrimSpace(spec.Schedule)
	spec.Command = strings.TrimSpace(spec.Command)
	spec.SiteName = strings.TrimSpace(spec.SiteName)
	spec.WorkingDirectory = strings.TrimSpace(spec.WorkingDirectory)
	if !usernamePattern.MatchString(spec.User) {
		return "", ErrInvalidUsername
	}
	if spec.ID == "" {
		return "", fmt.Errorf("cron job id is required")
	}
	if !isValidCronSchedule(spec.Schedule) {
		return "", ErrInvalidCronSchedule
	}
	if spec.Command == "" {
		return "", ErrInvalidCronCommand
	}
	if spec.RunInSiteRoot && !filepath.IsAbs(spec.WorkingDirectory) {
		return "", ErrInvalidTargetDirectory
	}
	current, err := readUserCrontab(spec.User)
	if err != nil {
		return "", err
	}
	lines := strings.Split(current, "\n")
	updated := make([]string, 0, len(lines))
	replaced := false
	updatedLine := ""
	pendingMetadata := ""
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		if metadata, ok := parseManagedMetadataComment(line); ok {
			pendingMetadata = metadata
			continue
		}
		job, ok := parseCronJobLineWithMetadata(line, pendingMetadata)
		metadataLine := ""
		if pendingMetadata != "" {
			metadataLine = cronManagedPrefix + pendingMetadata
		}
		pendingMetadata = ""
		if ok && job.Managed && job.ID == spec.ID {
			logPath := job.LogPath
			if logPath == "" {
				logPath, err = resolveCronLogPath(spec.User, spec.SiteName, spec.ID)
				if err != nil {
					return "", err
				}
			}
			if err := ensureCronLogWritable(spec.User, logPath); err != nil {
				return "", err
			}
			updatedLine = buildManagedCronLine(spec.ID, logPath, CronJobSpec{
				User:             spec.User,
				Schedule:         spec.Schedule,
				Command:          spec.Command,
				SiteName:         spec.SiteName,
				WorkingDirectory: spec.WorkingDirectory,
				RunInSiteRoot:    spec.RunInSiteRoot,
			})
			updated = append(updated, updatedLine)
			replaced = true
			continue
		}
		if metadataLine != "" {
			updated = append(updated, metadataLine)
		}
		updated = append(updated, line)
	}
	if !replaced {
		return "", fmt.Errorf("managed cron job could not be found")
	}
	if err := writeUserCrontab(spec.User, strings.Join(updated, "\n")); err != nil {
		return "", err
	}
	return updatedLine, nil
}

func DeleteCronJob(spec CronJobDeleteSpec) (string, error) {
	spec.User = strings.TrimSpace(spec.User)
	spec.ID = strings.TrimSpace(spec.ID)
	spec.RawLine = strings.TrimSpace(spec.RawLine)
	if !usernamePattern.MatchString(spec.User) {
		return "", ErrInvalidUsername
	}
	current, err := readUserCrontab(spec.User)
	if err != nil {
		return "", err
	}
	lines := strings.Split(current, "\n")
	updated := make([]string, 0, len(lines))
	removedLine := ""
	removed := false
	pendingMetadata := ""
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		trimmed := strings.TrimSpace(line)
		if metadata, ok := parseManagedMetadataComment(line); ok {
			pendingMetadata = metadata
			continue
		}
		if !removed {
			job, ok := parseCronJobLineWithMetadata(line, pendingMetadata)
			metadataLine := ""
			if pendingMetadata != "" {
				metadataLine = cronManagedPrefix + pendingMetadata
			}
			pendingMetadata = ""
			if ok {
				if spec.ID != "" && job.ID != "" && job.ID == spec.ID {
					removed = true
					removedLine = job.RawLine
					continue
				}
				if spec.ID == "" && spec.RawLine != "" && strings.TrimSpace(job.RawLine) == spec.RawLine {
					removed = true
					removedLine = job.RawLine
					continue
				}
			}
			if spec.ID == "" && spec.RawLine != "" && trimmed == spec.RawLine {
				removed = true
				removedLine = trimmed
				continue
			}
			if metadataLine != "" {
				updated = append(updated, metadataLine)
			}
			updated = append(updated, line)
			continue
		}
		pendingMetadata = ""
		updated = append(updated, line)
	}
	if !removed {
		return "", fmt.Errorf("cron job could not be found")
	}
	if err := writeUserCrontab(spec.User, strings.Join(updated, "\n")); err != nil {
		return "", err
	}
	return removedLine, nil
}

func ClearCronJobLog(user string, id string) (string, error) {
	job, err := findManagedCronJob(user, id)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(job.LogPath) == "" {
		return "", fmt.Errorf("cron job does not have a log path")
	}
	if err := ensureCronLogWritable(user, job.LogPath); err != nil {
		return "", err
	}
	if err := os.WriteFile(job.LogPath, []byte{}, 0o644); err != nil {
		return "", fmt.Errorf("clear cron log: %w", err)
	}
	return job.LogPath, nil
}

func RotateCronJobLog(user string, id string) (string, error) {
	job, err := findManagedCronJob(user, id)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(job.LogPath) == "" {
		return "", fmt.Errorf("cron job does not have a log path")
	}
	if err := ensureCronLogWritable(user, job.LogPath); err != nil {
		return "", err
	}
	if _, err := os.Stat(job.LogPath); err != nil {
		if os.IsNotExist(err) {
			if err := os.WriteFile(job.LogPath, []byte{}, 0o644); err != nil {
				return "", fmt.Errorf("create cron log: %w", err)
			}
			return job.LogPath, nil
		}
		return "", fmt.Errorf("inspect cron log: %w", err)
	}
	rotatedPath := job.LogPath + "." + time.Now().Format("20060102-150405")
	if err := os.Rename(job.LogPath, rotatedPath); err != nil {
		return "", fmt.Errorf("rotate cron log: %w", err)
	}
	if err := os.WriteFile(job.LogPath, []byte{}, 0o644); err != nil {
		return "", fmt.Errorf("recreate cron log: %w", err)
	}
	return rotatedPath, nil
}

func readUserCrontab(user string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "crontab", "-u", user, "-l")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if strings.Contains(strings.ToLower(message), "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("read crontab: %w: %s", err, message)
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

func writeUserCrontab(user string, content string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "crontab", "-u", user, "-")
	cmd.Stdin = strings.NewReader(strings.TrimRight(content, "\n") + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write crontab: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func appendCronLine(current string, line string) string {
	current = strings.TrimRight(current, "\n")
	if current == "" {
		return line
	}
	return current + "\n" + line
}

func buildManagedCronLine(id string, logPath string, spec CronJobSpec) string {
	metadata := managedCronMetadata{
		ID:   id,
		Site: spec.SiteName,
		Root: boolToFlag(spec.RunInSiteRoot),
		Cmd:  spec.Command,
		Log:  logPath,
	}
	if spec.WorkingDirectory != "" {
		metadata.CWD = spec.WorkingDirectory
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return spec.Schedule + " " + renderCronCommand(spec, logPath)
	}
	encodedMetadata := base64.RawURLEncoding.EncodeToString(metadataJSON)
	return cronManagedPrefix + "b64:" + encodedMetadata + "\n" + spec.Schedule + " " + renderCronCommand(spec, logPath)
}


func renderCronCommand(spec CronJobSpec, logPath string) string {
	baseCommand := escapeCronPercents(strings.TrimSpace(spec.Command))
	if spec.RunInSiteRoot {
		baseCommand = "cd " + shellQuote(spec.WorkingDirectory) + " && " + baseCommand
	}
	logDirectory := filepath.Dir(logPath)
	shellCommand := "mkdir -p " + shellQuote(logDirectory) +
		" && { echo; echo \"[$(date -Iseconds)] job start\"; . ~/.nvm/nvm.sh 2>/dev/null || true; " +
		baseCommand +
		"; status=$?; echo \"[$(date -Iseconds)] exit $status\"; exit \"$status\"; } >> " + shellQuote(logPath) + " 2>&1"
	return escapeCronPercents("/bin/bash -lc " + shellQuote(shellCommand))
}

func escapeCronPercents(value string) string {
	return strings.ReplaceAll(value, "%", "\\%")
}

func parseCronJobLine(line string) (CronJob, bool) {
	return parseCronJobLineWithMetadata(line, "")
}

func parseCronJobLineWithMetadata(line string, metadataComment string) (CronJob, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "@") && !strings.Contains(trimmed, " ") {
		return CronJob{}, false
	}
	schedule, command, ok := splitCronScheduleCommand(trimmed)
	if !ok {
		return CronJob{}, false
	}
	job := CronJob{Schedule: schedule, Command: command, RawLine: trimmed}
	commentPart := strings.TrimSpace(metadataComment)
	if commentPart != "" {
		if strings.HasPrefix(commentPart, "b64:") {
			encoded := strings.TrimSpace(strings.TrimPrefix(commentPart, "b64:"))
			if decoded, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
				var metadata managedCronMetadata
				if err := json.Unmarshal(decoded, &metadata); err == nil {
					job.Managed = true
					job.ID = metadata.ID
					job.SiteName = metadata.Site
					job.RunInSiteRoot = metadata.Root == "1"
					job.LogPath = metadata.Log
					if strings.TrimSpace(metadata.Cmd) != "" {
						job.Command = metadata.Cmd
					}
				}
			}
		} else {
			legacyMetadata := decodeLegacyManagedCronMetadata(commentPart)
			if legacyMetadata != nil {
				job.Managed = true
				job.ID = legacyMetadata.ID
				job.SiteName = legacyMetadata.Site
				job.RunInSiteRoot = legacyMetadata.Root == "1"
				job.LogPath = legacyMetadata.Log
				if strings.TrimSpace(legacyMetadata.Cmd) != "" {
					job.Command = legacyMetadata.Cmd
				}
			}
		}
	}
	return job, true
}

func parseManagedMetadataComment(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, cronManagedPrefix) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmed, cronManagedPrefix)), true
}

func parseCronJobs(content string) []CronJob {
	lines := strings.Split(content, "\n")
	jobs := make([]CronJob, 0, len(lines))
	pendingMetadata := ""
	for _, line := range lines {
		if metadata, ok := parseManagedMetadataComment(line); ok {
			pendingMetadata = metadata
			continue
		}
		job, ok := parseCronJobLineWithMetadata(line, pendingMetadata)
		pendingMetadata = ""
		if ok {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func decodeLegacyManagedCronMetadata(raw string) *managedCronMetadata {
	values, err := parseLegacyManagedMetadata(raw)
	if err != nil {
		return nil
	}
	return &managedCronMetadata{
		ID:   values["id"],
		Site: values["site"],
		Root: values["root"],
		Cmd:  values["cmd"],
		Log:  values["log"],
		CWD:  values["cwd"],
	}
}

func parseLegacyManagedMetadata(raw string) (map[string]string, error) {
	result := map[string]string{}
	for _, part := range strings.Split(strings.TrimSpace(raw), "&") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		pieces := strings.SplitN(part, "=", 2)
		if len(pieces) != 2 {
			continue
		}
		key := strings.TrimSpace(pieces[0])
		value := strings.TrimSpace(pieces[1])
		decodedValue, err := legacyPercentDecode(value)
		if err != nil {
			return nil, err
		}
		result[key] = strings.ReplaceAll(decodedValue, "+", " ")
	}
	return result, nil
}

func legacyPercentDecode(value string) (string, error) {
	value = strings.ReplaceAll(value, "+", " ")
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			builder.WriteByte(value[index])
			continue
		}
		if index+2 >= len(value) {
			return "", fmt.Errorf("invalid escape sequence")
		}
		decoded, err := strconv.ParseUint(value[index+1:index+3], 16, 8)
		if err != nil {
			return "", err
		}
		builder.WriteByte(byte(decoded))
		index += 2
	}
	return builder.String(), nil
}

func splitCronScheduleCommand(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	if strings.HasPrefix(line, "@") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return "", "", false
		}
		schedule := parts[0]
		command := strings.TrimSpace(line[len(schedule):])
		return schedule, command, command != ""
	}
	fieldCount := 0
	inField := false
	for index, char := range line {
		if char == ' ' || char == '\t' {
			if inField {
				fieldCount++
				inField = false
				if fieldCount == 5 {
					command := strings.TrimSpace(line[index:])
					schedule := strings.TrimSpace(line[:index])
					return schedule, command, command != ""
				}
			}
			continue
		}
		inField = true
	}
	return "", "", false
}

func isValidCronSchedule(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "@") {
		switch value {
		case "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
			return true
		default:
			return false
		}
	}
	return len(strings.Fields(value)) == 5
}

func randomCronID() (string, error) {
	buffer := make([]byte, 6)
	if _, err := crand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func resolveCronLogPath(user string, siteName string, id string) (string, error) {
	homeDirectory, err := lookupUserHome(user)
	if err != nil {
		return "", err
	}
	siteName = strings.TrimSpace(siteName)
	if siteName == "" {
		siteName = "general"
	}
	return filepath.Join(homeDirectory, ".ssc-cron", siteName, id+".log"), nil
}

func findManagedCronJob(user string, id string) (CronJob, error) {
	jobs, err := ListCronJobs(user)
	if err != nil {
		return CronJob{}, err
	}
	for _, job := range jobs {
		if job.Managed && job.ID == strings.TrimSpace(id) {
			return job, nil
		}
	}
	return CronJob{}, fmt.Errorf("managed cron job could not be found")
}

func ensureCronLogWritable(username string, logPath string) error {
	account, err := user.Lookup(strings.TrimSpace(username))
	if err != nil {
		return fmt.Errorf("lookup cron log user: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return fmt.Errorf("parse cron log uid: %w", err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return fmt.Errorf("parse cron log gid: %w", err)
	}
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("prepare cron log directory: %w", err)
	}
	if err := os.Chown(logDir, uid, gid); err != nil {
		return fmt.Errorf("set cron log directory owner: %w", err)
	}
	if _, err := os.Stat(logPath); err == nil {
		if err := os.Chown(logPath, uid, gid); err != nil {
			return fmt.Errorf("set cron log owner: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect cron log path: %w", err)
	}
	return nil
}

func boolToFlag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}