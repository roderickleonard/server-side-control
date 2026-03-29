//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var redisUsernamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

var ErrInvalidRedisUsername = errors.New("invalid redis username")
var ErrInvalidRedisPassword = errors.New("invalid redis password")
var ErrInvalidRedisPort = errors.New("invalid redis port")
var ErrInvalidRedisMaxMemory = errors.New("invalid redis maxmemory")
var ErrInvalidRedisEvictionPolicy = errors.New("invalid redis eviction policy")

var redisEvictionPolicies = map[string]struct{}{
	"noeviction":      {},
	"allkeys-lru":     {},
	"allkeys-lfu":     {},
	"allkeys-random":  {},
	"volatile-lru":    {},
	"volatile-lfu":    {},
	"volatile-random": {},
	"volatile-ttl":    {},
}

type redisManager struct {
	serviceName string
	configPath  string
	aclFilePath string
}

func NewRedisManager() RedisManager {
	return redisManager{
		serviceName: "redis-server",
		configPath:  "/etc/redis/redis.conf",
		aclFilePath: "/etc/redis/server-side-control.users.acl",
	}
}

func (m redisManager) Inspect() (RedisStatus, error) {
	status := RedisStatus{
		ServiceName: m.serviceName,
		ConfigPath:  m.configPath,
		ACLFilePath: m.aclFilePath,
		Port:        6379,
		EvictionPolicy: "noeviction",
	}

	if output, err := exec.Command("redis-server", "--version").CombinedOutput(); err == nil {
		status.Installed = true
		status.Version = strings.TrimSpace(string(output))
	}

	if content, err := os.ReadFile(m.configPath); err == nil {
		status.Installed = true
		port, aclPath, maxMemoryBytes, evictionPolicy := parseRedisConfig(string(content))
		if port > 0 {
			status.Port = port
		}
		if aclPath != "" {
			status.ACLFilePath = aclPath
		}
		if maxMemoryBytes >= 0 {
			status.MaxMemoryBytes = maxMemoryBytes
		}
		if evictionPolicy != "" {
			status.EvictionPolicy = evictionPolicy
		}
	} else if !os.IsNotExist(err) {
		return status, fmt.Errorf("read redis config: %w", err)
	}

	status.Active = systemctlCheck("is-active", m.serviceName)
	status.Enabled = systemctlCheck("is-enabled", m.serviceName)

	username, err := readRedisACLUsername(status.ACLFilePath)
	if err == nil {
		status.Username = username
	} else if !os.IsNotExist(err) {
		return status, err
	}

	return status, nil
}

func (m redisManager) Install() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-lc", "set -euo pipefail\napt-get update\nDEBIAN_FRONTEND=noninteractive apt-get install -y redis-server\nsystemctl enable redis-server\nsystemctl restart redis-server\nsystemctl is-active redis-server")
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("install redis-server: %w", err)
	}
	return result, nil
}

func (m redisManager) Configure(spec RedisConfigSpec) (string, error) {
	username := strings.TrimSpace(spec.Username)
	password := strings.TrimSpace(spec.Password)
	if !redisUsernamePattern.MatchString(username) {
		return "", ErrInvalidRedisUsername
	}
	if password == "" || strings.ContainsAny(password, " \t\r\n") {
		return "", ErrInvalidRedisPassword
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return "", ErrInvalidRedisPort
	}
	if spec.MaxMemoryBytes < 0 {
		return "", ErrInvalidRedisMaxMemory
	}
	policy := strings.TrimSpace(spec.EvictionPolicy)
	if policy == "" {
		policy = "noeviction"
	}
	if _, ok := redisEvictionPolicies[policy]; !ok {
		return "", ErrInvalidRedisEvictionPolicy
	}

	content, err := os.ReadFile(m.configPath)
	if err != nil {
		return "", fmt.Errorf("read redis config: %w", err)
	}

	updated := upsertRedisDirective(string(content), "port", strconv.Itoa(spec.Port))
	updated = upsertRedisDirective(updated, "aclfile", m.aclFilePath)
	updated = upsertRedisDirective(updated, "maxmemory", strconv.FormatInt(spec.MaxMemoryBytes, 10))
	updated = upsertRedisDirective(updated, "maxmemory-policy", policy)
	updated = disableRedisDirective(updated, "requirepass", "disabled by Server Side Control in favor of ACL users")

	if err := writeRedisACLFile(m.aclFilePath, username, password); err != nil {
		return "", err
	}
	if err := os.WriteFile(m.configPath, []byte(updated), 0o644); err != nil {
		return "", fmt.Errorf("write redis config: %w", err)
	}

	return fmt.Sprintf("Redis config updated: %s\nRedis ACL updated: %s\nMax memory: %d bytes\nEviction policy: %s", m.configPath, m.aclFilePath, spec.MaxMemoryBytes, policy), nil
}

func (m redisManager) Start() (string, error) {
	return runRedisServiceCommand("start", m.serviceName)
}

func (m redisManager) Stop() (string, error) {
	return runRedisServiceCommand("stop", m.serviceName)
}

func (m redisManager) Restart() (string, error) {
	return runRedisServiceCommand("restart", m.serviceName)
}

func (m redisManager) TestConnection(spec RedisPingSpec) (string, error) {
	username := strings.TrimSpace(spec.Username)
	password := strings.TrimSpace(spec.Password)
	if !redisUsernamePattern.MatchString(username) {
		return "", ErrInvalidRedisUsername
	}
	if password == "" || strings.ContainsAny(password, " \t\r\n") {
		return "", ErrInvalidRedisPassword
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return "", ErrInvalidRedisPort
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "redis-cli", "--user", username, "-a", password, "-p", strconv.Itoa(spec.Port), "PING")
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("redis ping failed: %w", err)
	}
	if !strings.EqualFold(result, "PONG") {
		return result, fmt.Errorf("unexpected redis ping response: %s", result)
	}
	return result, nil
}

func (m redisManager) Logs(lines int) (string, error) {
	if lines <= 0 || lines > 1000 {
		lines = 200
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := fmt.Sprintf("set -euo pipefail\nif command -v journalctl >/dev/null 2>&1; then\n  journalctl -u %s -n %d --no-pager\nelse\n  tail -n %d /var/log/redis/redis-server.log\nfi", m.serviceName, lines, lines)
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	output, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("read redis logs: %w", err)
	}
	return result, nil
}

func parseRedisConfig(content string) (int, string, int64, string) {
	port := 6379
	aclPath := ""
	maxMemoryBytes := int64(0)
	evictionPolicy := "noeviction"
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "port":
			if value, err := strconv.Atoi(fields[1]); err == nil && value > 0 {
				port = value
			}
		case "aclfile":
			aclPath = fields[1]
		case "maxmemory":
			if value, err := strconv.ParseInt(fields[1], 10, 64); err == nil && value >= 0 {
				maxMemoryBytes = value
			}
		case "maxmemory-policy":
			evictionPolicy = fields[1]
		}
	}
	return port, aclPath, maxMemoryBytes, evictionPolicy
}

func readRedisACLUsername(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || fields[0] != "user" {
			continue
		}
		if fields[1] == "default" {
			continue
		}
		return fields[1], nil
	}
	return "", nil
}

func writeRedisACLFile(path string, username string, password string) error {
	content := fmt.Sprintf("user default off\nuser %s on >%s ~* &* +@all\n", username, password)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create redis acl dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		return fmt.Errorf("write redis acl file: %w", err)
	}
	redisUser, err := user.Lookup("redis")
	if err != nil {
		return nil
	}
	uid, uidErr := strconv.Atoi(redisUser.Uid)
	gid, gidErr := strconv.Atoi(redisUser.Gid)
	if uidErr != nil || gidErr != nil {
		return nil
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown redis acl file: %w", err)
	}
	return nil
}

func upsertRedisDirective(content string, key string, value string) string {
	lines := strings.Split(content, "\n")
	replacement := key + " " + value
	updated := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		normalized := strings.TrimLeft(trimmed, "#; ")
		if normalized != key && !strings.HasPrefix(normalized, key+" ") {
			continue
		}
		if !updated {
			lines[i] = leadingWhitespace(line) + replacement
			updated = true
			continue
		}
		lines[i] = "# " + normalized
	}
	if !updated {
		lines = append(lines, replacement)
	}
	return strings.Join(lines, "\n")
}

func disableRedisDirective(content string, key string, reason string) string {
	lines := strings.Split(content, "\n")
	comment := fmt.Sprintf("# %s %s", key, reason)
	disabled := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		normalized := strings.TrimLeft(trimmed, "#; ")
		if normalized != key && !strings.HasPrefix(normalized, key+" ") {
			continue
		}
		if !disabled {
			lines[i] = comment
			disabled = true
			continue
		}
		lines[i] = ""
	}
	if !disabled {
		lines = append(lines, comment)
	}
	return strings.Join(lines, "\n")
}

func leadingWhitespace(value string) string {
	for i, r := range value {
		if r != ' ' && r != '\t' {
			return value[:i]
		}
	}
	return value
}

func systemctlCheck(action string, service string) bool {
	cmd := exec.Command("systemctl", action, "--quiet", service)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func runRedisServiceCommand(action string, service string) (string, error) {
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