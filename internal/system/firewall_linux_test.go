//go:build linux

package system

import (
	"testing"
)

func TestValidateFirewallRuleSpec(t *testing.T) {
	t.Run("valid allow tcp any", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "tcp", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("valid deny udp specific IP", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "53", Protocol: "udp", Source: "10.0.0.1", Action: "deny"}
		if err := validateFirewallRuleSpec(spec); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("valid port range", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "8000:8100", Protocol: "tcp", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != nil {
			t.Errorf("expected no error for port range, got %v", err)
		}
	})

	t.Run("valid CIDR source", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "443", Protocol: "tcp", Source: "192.168.1.0/24", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != nil {
			t.Errorf("expected no error for CIDR source, got %v", err)
		}
	})

	t.Run("valid protocol any", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "any", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != nil {
			t.Errorf("expected no error for protocol any, got %v", err)
		}
	})

	t.Run("empty port returns error", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "", Protocol: "tcp", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallPort {
			t.Errorf("expected ErrInvalidFirewallPort, got %v", err)
		}
	})

	t.Run("invalid port number too large", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "999999", Protocol: "tcp", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallPort {
			t.Errorf("expected ErrInvalidFirewallPort, got %v", err)
		}
	})

	t.Run("invalid port non-numeric", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "http", Protocol: "tcp", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallPort {
			t.Errorf("expected ErrInvalidFirewallPort, got %v", err)
		}
	})

	t.Run("invalid protocol icmp", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "icmp", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallProto {
			t.Errorf("expected ErrInvalidFirewallProto, got %v", err)
		}
	})

	t.Run("invalid protocol empty", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "", Source: "any", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallProto {
			t.Errorf("expected ErrInvalidFirewallProto, got %v", err)
		}
	})

	t.Run("invalid source hostname", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "tcp", Source: "example.com", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallSource {
			t.Errorf("expected ErrInvalidFirewallSource, got %v", err)
		}
	})

	t.Run("invalid source empty", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "tcp", Source: "", Action: "allow"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallSource {
			t.Errorf("expected ErrInvalidFirewallSource, got %v", err)
		}
	})

	t.Run("invalid action reject", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "tcp", Source: "any", Action: "reject"}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallAction {
			t.Errorf("expected ErrInvalidFirewallAction, got %v", err)
		}
	})

	t.Run("invalid action empty", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "tcp", Source: "any", Action: ""}
		if err := validateFirewallRuleSpec(spec); err != ErrInvalidFirewallAction {
			t.Errorf("expected ErrInvalidFirewallAction, got %v", err)
		}
	})

	t.Run("case insensitive protocol and action", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "TCP", Source: "any", Action: "ALLOW"}
		if err := validateFirewallRuleSpec(spec); err != nil {
			t.Errorf("expected no error for uppercase protocol/action, got %v", err)
		}
	})
}

func TestBuildUFWArgs(t *testing.T) {
	t.Run("allow tcp from any", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "tcp", Source: "any", Action: "allow"}
		args := buildUFWArgs(spec)
		want := []string{"allow", "80/tcp"}
		if len(args) != len(want) {
			t.Fatalf("expected args %v, got %v", want, args)
		}
		for i, a := range args {
			if a != want[i] {
				t.Errorf("arg[%d]: want %q, got %q", i, want[i], a)
			}
		}
	})

	t.Run("deny udp from any", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "53", Protocol: "udp", Source: "any", Action: "deny"}
		args := buildUFWArgs(spec)
		want := []string{"deny", "53/udp"}
		if len(args) != len(want) {
			t.Fatalf("expected args %v, got %v", want, args)
		}
		for i, a := range args {
			if a != want[i] {
				t.Errorf("arg[%d]: want %q, got %q", i, want[i], a)
			}
		}
	})

	t.Run("allow any protocol from any omits proto suffix", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "8080", Protocol: "any", Source: "any", Action: "allow"}
		args := buildUFWArgs(spec)
		want := []string{"allow", "8080"}
		if len(args) != len(want) {
			t.Fatalf("expected args %v, got %v", want, args)
		}
		for i, a := range args {
			if a != want[i] {
				t.Errorf("arg[%d]: want %q, got %q", i, want[i], a)
			}
		}
	})

	t.Run("deny udp from specific IP", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "22", Protocol: "udp", Source: "10.0.0.5", Action: "deny"}
		args := buildUFWArgs(spec)
		want := []string{"deny", "from", "10.0.0.5", "to", "any", "port", "22", "proto", "udp"}
		if len(args) != len(want) {
			t.Fatalf("expected args %v, got %v", want, args)
		}
		for i, a := range args {
			if a != want[i] {
				t.Errorf("arg[%d]: want %q, got %q", i, want[i], a)
			}
		}
	})

	t.Run("allow any protocol from specific IP omits proto", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "443", Protocol: "any", Source: "192.168.1.0/24", Action: "allow"}
		args := buildUFWArgs(spec)
		want := []string{"allow", "from", "192.168.1.0/24", "to", "any", "port", "443"}
		if len(args) != len(want) {
			t.Fatalf("expected args %v, got %v", want, args)
		}
		for i, a := range args {
			if a != want[i] {
				t.Errorf("arg[%d]: want %q, got %q", i, want[i], a)
			}
		}
	})

	t.Run("source any is not included in args", func(t *testing.T) {
		spec := FirewallRuleSpec{Port: "80", Protocol: "tcp", Source: "any", Action: "allow"}
		args := buildUFWArgs(spec)
		for _, a := range args {
			if a == "from" {
				t.Error("expected 'from' not to appear when source is 'any'")
			}
		}
	})
}

func TestParseUFWStatus(t *testing.T) {
	t.Run("active with rules", func(t *testing.T) {
		output := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere
[ 3] 443/tcp                    ALLOW IN    Anywhere
[ 4] 8080                       DENY IN     192.168.1.0/24
`
		status := parseUFWStatus(output)

		if !status.Active {
			t.Error("expected Active=true")
		}
		if len(status.Rules) != 4 {
			t.Fatalf("expected 4 rules, got %d", len(status.Rules))
		}

		// Rule 1
		if status.Rules[0].Number != 1 {
			t.Errorf("rule[0].Number: want 1, got %d", status.Rules[0].Number)
		}
		if status.Rules[0].To != "22/tcp" {
			t.Errorf("rule[0].To: want %q, got %q", "22/tcp", status.Rules[0].To)
		}
		if status.Rules[0].Action != "ALLOW" {
			t.Errorf("rule[0].Action: want %q, got %q", "ALLOW", status.Rules[0].Action)
		}
		if status.Rules[0].From != "Anywhere" {
			t.Errorf("rule[0].From: want %q, got %q", "Anywhere", status.Rules[0].From)
		}

		// Rule 4 (DENY)
		if status.Rules[3].Number != 4 {
			t.Errorf("rule[3].Number: want 4, got %d", status.Rules[3].Number)
		}
		if status.Rules[3].To != "8080" {
			t.Errorf("rule[3].To: want %q, got %q", "8080", status.Rules[3].To)
		}
		if status.Rules[3].Action != "DENY" {
			t.Errorf("rule[3].Action: want %q, got %q", "DENY", status.Rules[3].Action)
		}
		if status.Rules[3].From != "192.168.1.0/24" {
			t.Errorf("rule[3].From: want %q, got %q", "192.168.1.0/24", status.Rules[3].From)
		}
	})

	t.Run("inactive status", func(t *testing.T) {
		output := "Status: inactive\n"
		status := parseUFWStatus(output)
		if status.Active {
			t.Error("expected Active=false for inactive status")
		}
		if len(status.Rules) != 0 {
			t.Errorf("expected 0 rules, got %d", len(status.Rules))
		}
	})

	t.Run("empty output", func(t *testing.T) {
		status := parseUFWStatus("")
		if status.Active {
			t.Error("expected Active=false for empty output")
		}
		if len(status.Rules) != 0 {
			t.Errorf("expected 0 rules, got %d", len(status.Rules))
		}
	})

	t.Run("IPv6 rules are skipped", func(t *testing.T) {
		output := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
`
		status := parseUFWStatus(output)
		if !status.Active {
			t.Error("expected Active=true")
		}
		// Only the non-v6 rule should be included
		if len(status.Rules) != 1 {
			t.Errorf("expected 1 rule (IPv6 skipped), got %d", len(status.Rules))
		}
	})

	t.Run("rules have correct sequential numbers", func(t *testing.T) {
		output := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 80/tcp                     ALLOW IN    Anywhere
[ 2] 443/tcp                    ALLOW IN    Anywhere
[ 3] 8080                       DENY IN     10.0.0.1
`
		status := parseUFWStatus(output)
		for i, rule := range status.Rules {
			if rule.Number != i+1 {
				t.Errorf("rule[%d].Number: want %d, got %d", i, i+1, rule.Number)
			}
		}
	})
}
