package system

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrFirewallUFWNotFound    = errors.New("ufw is not installed")
	ErrInvalidFirewallPort    = errors.New("port must be a number or range like 8000:8100")
	ErrInvalidFirewallProto   = errors.New("protocol must be tcp, udp, or any")
	ErrInvalidFirewallSource  = errors.New("source must be 'any' or a valid IP/CIDR")
	ErrInvalidFirewallAction  = errors.New("action must be 'allow' or 'deny'")
	ErrInvalidFirewallRuleNum = errors.New("rule number must be a positive integer")
)

var (
	firewallPortPattern   = regexp.MustCompile(`^\d{1,5}(:\d{1,5})?$`)
	firewallSourcePattern = regexp.MustCompile(`^(any|(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?)$`)
	firewallRuleRe        = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY)\s+(?:IN\s+)?(.+?)\s*$`)
)

type linuxFirewallManager struct{}

func NewLinuxFirewallManager() FirewallManager {
	return &linuxFirewallManager{}
}

func (m *linuxFirewallManager) Status() (FirewallStatus, error) {
	if _, err := exec.LookPath("ufw"); err != nil {
		return FirewallStatus{}, ErrFirewallUFWNotFound
	}
	out, err := exec.Command("ufw", "status", "numbered").Output()
	if err != nil {
		return FirewallStatus{}, fmt.Errorf("ufw status: %w", err)
	}
	return parseUFWStatus(string(out)), nil
}

func (m *linuxFirewallManager) Enable() (string, error) {
	if _, err := exec.LookPath("ufw"); err != nil {
		return "", ErrFirewallUFWNotFound
	}
	cmd := exec.Command("ufw", "--force", "enable")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func (m *linuxFirewallManager) Disable() (string, error) {
	if _, err := exec.LookPath("ufw"); err != nil {
		return "", ErrFirewallUFWNotFound
	}
	cmd := exec.Command("ufw", "disable")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func (m *linuxFirewallManager) AddRule(spec FirewallRuleSpec) (string, error) {
	if err := validateFirewallRuleSpec(spec); err != nil {
		return "", err
	}
	args := buildUFWArgs(spec)
	cmd := exec.Command("ufw", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func (m *linuxFirewallManager) DeleteRule(number int) (string, error) {
	if number < 1 {
		return "", ErrInvalidFirewallRuleNum
	}
	cmd := exec.Command("ufw", "--force", "delete", strconv.Itoa(number))
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func validateFirewallRuleSpec(spec FirewallRuleSpec) error {
	if !firewallPortPattern.MatchString(spec.Port) {
		return ErrInvalidFirewallPort
	}
	proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if proto != "tcp" && proto != "udp" && proto != "any" {
		return ErrInvalidFirewallProto
	}
	src := strings.ToLower(strings.TrimSpace(spec.Source))
	if !firewallSourcePattern.MatchString(src) {
		return ErrInvalidFirewallSource
	}
	action := strings.ToLower(strings.TrimSpace(spec.Action))
	if action != "allow" && action != "deny" {
		return ErrInvalidFirewallAction
	}
	return nil
}

func buildUFWArgs(spec FirewallRuleSpec) []string {
	action := strings.ToLower(strings.TrimSpace(spec.Action))
	proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
	src := strings.ToLower(strings.TrimSpace(spec.Source))

	// Simple form: ufw allow/deny PORT[/PROTO]
	if src == "any" {
		if proto == "any" {
			return []string{action, spec.Port}
		}
		return []string{action, spec.Port + "/" + proto}
	}
	// Source-scoped form: ufw allow/deny from SRC to any port PORT [proto PROTO]
	args := []string{action, "from", src, "to", "any", "port", spec.Port}
	if proto != "any" {
		args = append(args, "proto", proto)
	}
	return args
}

func parseUFWStatus(output string) FirewallStatus {
	status := FirewallStatus{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Status: active") {
			status.Active = true
			continue
		}
		// Skip IPv6 duplicate rules
		if strings.Contains(line, "(v6)") {
			continue
		}
		m := firewallRuleRe.FindStringSubmatch(line)
		if len(m) != 5 {
			continue
		}
		num, err := strconv.Atoi(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		status.Rules = append(status.Rules, FirewallRule{
			Number: num,
			To:     strings.TrimSpace(m[2]),
			Action: strings.TrimSpace(m[3]),
			From:   strings.TrimSpace(m[4]),
		})
	}
	return status
}
