//go:build !linux

package system

import "fmt"

type stubFirewallManager struct{}

func NewLinuxFirewallManager() FirewallManager {
	return stubFirewallManager{}
}

func (stubFirewallManager) Status() (FirewallStatus, error) {
	return FirewallStatus{}, fmt.Errorf("firewall management is only supported on Linux hosts")
}

func (stubFirewallManager) Enable() (string, error) {
	return "", fmt.Errorf("firewall management is only supported on Linux hosts")
}

func (stubFirewallManager) Disable() (string, error) {
	return "", fmt.Errorf("firewall management is only supported on Linux hosts")
}

func (stubFirewallManager) AddRule(spec FirewallRuleSpec) (string, error) {
	return "", fmt.Errorf("firewall management is only supported on Linux hosts")
}

func (stubFirewallManager) DeleteRule(number int) (string, error) {
	return "", fmt.Errorf("firewall management is only supported on Linux hosts")
}
