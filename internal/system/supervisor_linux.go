//go:build linux

package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var supervisorProgramPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$`)
var supervisorUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var ErrInvalidSupervisorProgramName = errors.New("invalid supervisor program name")
var ErrInvalidSupervisorCommand = errors.New("invalid supervisor command")
var ErrInvalidSupervisorDirectory = errors.New("invalid supervisor directory")
var ErrInvalidSupervisorUser = errors.New("invalid supervisor user")
var ErrInvalidSupervisorLogPath = errors.New("invalid supervisor log path")
var ErrSupervisorManagedProgramOnly = errors.New("only panel-managed supervisor programs can be deleted")

const supervisorManagedPrefix = "server-side-control-"

type supervisorManager struct {
	serviceName string
	configDir   string
	logDir      string
}

func NewSupervisorManager() SupervisorManager {
	return supervisorManager{
		serviceName: "supervisor",
		configDir:   "/etc/supervisor/conf.d",
		logDir:      "/var/log/supervisor",
	}
}

func (m supervisorManager) Inspect() (SupervisorStatus, error) {
	status := SupervisorStatus{
		ServiceName:     m.serviceName,
		ConfigDirectory: m.configDir,
	}
	if output, err := exec.Command("supervisord", "--version").CombinedOutput(); err == nil {
		status.Installed = true
		status.Version = strings.TrimSpace(string(output))
	}
	if _, err := os.Stat(m.configDir); err == nil {
		status.Installed = true
	}
	status.Active = systemctlCheck("is-active", m.serviceName)
	status.Enabled = systemctlCheck("is-enabled", m.serviceName)
	return status, nil
}

func (m supervisorManager) Install() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-lc", "set -euo pipefail\napt-get update\nDEBIAN_FRONTEND=noninteractive apt-get install -y supervisor\nsystemctl enable supervisor\nsystemctl restart supervisor\nsystemctl is-active supervisor")
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("install supervisor: %w", err)
	}
	return result, nil
}

func (m supervisorManager) Start() (string, error) {
	return runSupervisorServiceCommand("start", m.serviceName)
}

func (m supervisorManager) Stop() (string, error) {
	return runSupervisorServiceCommand("stop", m.serviceName)
}

func (m supervisorManager) Restart() (string, error) {
	return runSupervisorServiceCommand("restart", m.serviceName)
}

func (m supervisorManager) Reread() (string, error) {
	return runSupervisorctl("reread")
}

func (m supervisorManager) Update() (string, error) {
	return runSupervisorctl("update")
}

func (m supervisorManager) ListPrograms() ([]SupervisorProgram, error) {
	statusMap := supervisorStatusMap()
	paths, err := filepath.Glob(filepath.Join(m.configDir, "*.conf"))
	if err != nil {
		return nil, fmt.Errorf("list supervisor configs: %w", err)
	}
	items := make([]SupervisorProgram, 0)
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		items = append(items, parseSupervisorPrograms(string(content), path, statusMap)...)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Managed != items[j].Managed {
			return items[i].Managed
		}
		return items[i].Name < items[j].Name
	})
	return items, nil
}

func (m supervisorManager) SaveProgram(spec SupervisorProgramSpec) (string, error) {
	name := strings.TrimSpace(spec.Name)
	command := strings.TrimSpace(spec.Command)
	directory := strings.TrimSpace(spec.Directory)
	user := strings.TrimSpace(spec.User)
	stdoutLogfile := strings.TrimSpace(spec.StdoutLogfile)
	stderrLogfile := strings.TrimSpace(spec.StderrLogfile)
	if !supervisorProgramPattern.MatchString(name) {
		return "", ErrInvalidSupervisorProgramName
	}
	if command == "" {
		return "", ErrInvalidSupervisorCommand
	}
	if directory != "" && !filepath.IsAbs(directory) {
		return "", ErrInvalidSupervisorDirectory
	}
	if user != "" && !supervisorUserPattern.MatchString(user) {
		return "", ErrInvalidSupervisorUser
	}
	if stdoutLogfile == "" {
		stdoutLogfile = filepath.Join(m.logDir, name+".log")
	}
	if stderrLogfile == "" {
		stderrLogfile = filepath.Join(m.logDir, name+"-error.log")
	}
	if !filepath.IsAbs(stdoutLogfile) || !filepath.IsAbs(stderrLogfile) {
		return "", ErrInvalidSupervisorLogPath
	}
	if err := os.MkdirAll(m.configDir, 0o755); err != nil {
		return "", fmt.Errorf("create supervisor config dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(stdoutLogfile), 0o755); err != nil {
		return "", fmt.Errorf("create supervisor log dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(stderrLogfile), 0o755); err != nil {
		return "", fmt.Errorf("create supervisor error log dir: %w", err)
	}
	configPath := filepath.Join(m.configDir, supervisorManagedPrefix+name+".conf")
	content := buildSupervisorProgramConfig(SupervisorProgramSpec{
		Name:          name,
		Command:       command,
		Directory:     directory,
		User:          user,
		AutoStart:     spec.AutoStart,
		AutoRestart:   spec.AutoRestart,
		StdoutLogfile: stdoutLogfile,
		StderrLogfile: stderrLogfile,
		Environment:   strings.TrimSpace(spec.Environment),
	})
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write supervisor config: %w", err)
	}
	rereadOutput, rereadErr := m.Reread()
	updateOutput, updateErr := m.Update()
	combined := strings.TrimSpace(strings.Join(filterEmptyStrings([]string{
		"Config saved: " + configPath,
		rereadOutput,
		updateOutput,
	}), "\n\n"))
	if rereadErr != nil {
		return combined, rereadErr
	}
	if updateErr != nil {
		return combined, updateErr
	}
	return combined, nil
}

func (m supervisorManager) RemoveProgram(spec SupervisorProgramActionSpec) (string, error) {
	name := strings.TrimSpace(spec.Name)
	if !supervisorProgramPattern.MatchString(name) {
		return "", ErrInvalidSupervisorProgramName
	}
	configPath := filepath.Join(m.configDir, supervisorManagedPrefix+name+".conf")
	if _, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) {
			return "", ErrSupervisorManagedProgramOnly
		}
		return "", fmt.Errorf("stat supervisor config: %w", err)
	}
	stopOutput, _ := runSupervisorctl("stop", name)
	if err := os.Remove(configPath); err != nil {
		return stopOutput, fmt.Errorf("remove supervisor config: %w", err)
	}
	rereadOutput, rereadErr := m.Reread()
	updateOutput, updateErr := m.Update()
	combined := strings.TrimSpace(strings.Join(filterEmptyStrings([]string{
		stopOutput,
		"Removed config: " + configPath,
		rereadOutput,
		updateOutput,
	}), "\n\n"))
	if rereadErr != nil {
		return combined, rereadErr
	}
	if updateErr != nil {
		return combined, updateErr
	}
	return combined, nil
}

func (m supervisorManager) StartProgram(spec SupervisorProgramActionSpec) (string, error) {
	return runSupervisorProgramCommand("start", spec.Name)
}

func (m supervisorManager) StopProgram(spec SupervisorProgramActionSpec) (string, error) {
	return runSupervisorProgramCommand("stop", spec.Name)
}

func (m supervisorManager) RestartProgram(spec SupervisorProgramActionSpec) (string, error) {
	return runSupervisorProgramCommand("restart", spec.Name)
}

func (m supervisorManager) TailProgramLogs(spec SupervisorLogSpec) (string, error) {
	name := strings.TrimSpace(spec.Name)
	if !supervisorProgramPattern.MatchString(name) {
		return "", ErrInvalidSupervisorProgramName
	}
	lines := spec.Lines
	if lines <= 0 || lines > 1000 {
		lines = 200
	}
	programs, _ := m.ListPrograms()
	var match *SupervisorProgram
	for i := range programs {
		if programs[i].Name == name {
			match = &programs[i]
			break
		}
	}
	stdoutPath := ""
	stderrPath := ""
	if match != nil {
		stdoutPath = strings.TrimSpace(match.StdoutLogfile)
		stderrPath = strings.TrimSpace(match.StderrLogfile)
	}
	sections := make([]string, 0, 2)
	if stdoutPath != "" {
		if stdoutOutput, err := tailFile(stdoutPath, lines); err == nil && strings.TrimSpace(stdoutOutput) != "" {
			sections = append(sections, "== stdout ==\n"+strings.TrimSpace(stdoutOutput))
		}
	}
	if stderrPath != "" {
		if stderrOutput, err := tailFile(stderrPath, lines); err == nil && strings.TrimSpace(stderrOutput) != "" {
			sections = append(sections, "== stderr ==\n"+strings.TrimSpace(stderrOutput))
		}
	}
	if len(sections) > 0 {
		return strings.Join(sections, "\n\n"), nil
	}
	stdoutOutput, stdoutErr := runSupervisorctl("tail", "-"+strconv.Itoa(lines), name, "stdout")
	stderrOutput, stderrErr := runSupervisorctl("tail", "-"+strconv.Itoa(lines), name, "stderr")
	if stdoutErr != nil && stderrErr != nil {
		if strings.TrimSpace(stdoutOutput) != "" {
			return strings.TrimSpace(stdoutOutput), stdoutErr
		}
		if strings.TrimSpace(stderrOutput) != "" {
			return strings.TrimSpace(stderrOutput), stderrErr
		}
		return "", stdoutErr
	}
	if strings.TrimSpace(stdoutOutput) != "" {
		sections = append(sections, "== stdout ==\n"+strings.TrimSpace(stdoutOutput))
	}
	if strings.TrimSpace(stderrOutput) != "" {
		sections = append(sections, "== stderr ==\n"+strings.TrimSpace(stderrOutput))
	}
	return strings.Join(sections, "\n\n"), nil
}

func parseSupervisorPrograms(content string, configPath string, statusMap map[string]string) []SupervisorProgram {
	programs := make([]SupervisorProgram, 0)
	var current *SupervisorProgram
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if current != nil {
				current.Status = firstNonEmptyString(statusMap[current.Name], current.Status)
				programs = append(programs, *current)
			}
			section := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if !strings.HasPrefix(section, "program:") {
				current = nil
				continue
			}
			name := strings.TrimSpace(strings.TrimPrefix(section, "program:"))
			current = &SupervisorProgram{
				Name:       name,
				ConfigPath: configPath,
				Managed:    strings.HasPrefix(filepath.Base(configPath), supervisorManagedPrefix),
				Status:     "unknown",
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		switch key {
		case "command":
			current.Command = value
		case "directory":
			current.Directory = value
		case "user":
			current.User = value
		case "autostart":
			current.AutoStart = parseSupervisorBool(value)
		case "autorestart":
			current.AutoRestart = parseSupervisorBool(value)
		case "stdout_logfile":
			current.StdoutLogfile = value
		case "stderr_logfile":
			current.StderrLogfile = value
		case "environment":
			current.Environment = value
		}
	}
	if current != nil {
		current.Status = firstNonEmptyString(statusMap[current.Name], current.Status)
		programs = append(programs, *current)
	}
	return programs
}

func parseSupervisorBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func buildSupervisorProgramConfig(spec SupervisorProgramSpec) string {
	lines := []string{
		"[program:" + spec.Name + "]",
		"command=" + spec.Command,
		"autostart=" + supervisorBoolString(spec.AutoStart),
		"autorestart=" + supervisorBoolString(spec.AutoRestart),
		"startsecs=3",
		"stopasgroup=true",
		"killasgroup=true",
		"stdout_logfile=" + spec.StdoutLogfile,
		"stderr_logfile=" + spec.StderrLogfile,
	}
	if spec.Directory != "" {
		lines = append(lines, "directory="+spec.Directory)
	}
	if spec.User != "" {
		lines = append(lines, "user="+spec.User)
	}
	if spec.Environment != "" {
		lines = append(lines, "environment="+spec.Environment)
	}
	return strings.Join(lines, "\n") + "\n"
}

func supervisorBoolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func supervisorStatusMap() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "supervisorctl", "status")
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) == 0 {
		return map[string]string{}
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		result[fields[0]] = fields[1]
	}
	return result
}

func runSupervisorServiceCommand(action string, service string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-lc", fmt.Sprintf("set -euo pipefail\nsystemctl %s %s\nsystemctl show %s --property=ActiveState --property=SubState --property=UnitFileState --no-pager", action, service, service))
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("%s %s: %w", action, service, err)
	}
	return result, nil
}

func runSupervisorProgramCommand(action string, name string) (string, error) {
	name = strings.TrimSpace(name)
	if !supervisorProgramPattern.MatchString(name) {
		return "", ErrInvalidSupervisorProgramName
	}
	return runSupervisorctl(action, name)
}

func runSupervisorctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "supervisorctl", args...)
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("supervisorctl %s: %w", strings.Join(args, " "), err)
	}
	return result, nil
}

func filterEmptyStrings(items []string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			continue
		}
		result = append(result, strings.TrimSpace(item))
	}
	return result
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func tailFile(path string, lines int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tail", "-n", strconv.Itoa(lines), path)
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("tail %s: %w", path, err)
	}
	return result, nil
}