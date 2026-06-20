package system

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeTLSDomains(t *testing.T) {
	cases := []struct {
		primary    string
		additional []string
		want       []string
	}{
		{"example.com", []string{"www.example.com"}, []string{"example.com", "www.example.com"}},
		{" Example.com ", []string{"WWW.example.com", "example.com"}, []string{"example.com", "www.example.com"}}, // trims, lowercases, dedupes primary
		{"example.com", nil, []string{"example.com"}},
		{"", []string{"www.example.com", ""}, []string{"www.example.com"}},
		{"a.com", []string{"a.com", "b.com", "b.com"}, []string{"a.com", "b.com"}},
	}
	for _, c := range cases {
		got := NormalizeTLSDomains(c.primary, c.additional)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("NormalizeTLSDomains(%q, %v) = %v, want %v", c.primary, c.additional, got, c.want)
		}
	}
}

func TestAddServerNameAliasesExtendsMatchingBlock(t *testing.T) {
	config := `server {
    listen 80;
    server_name example.com;
    location / { proxy_pass http://127.0.0.1:3000; }
}
`
	out, changed := AddServerNameAliases(config, "example.com", []string{"www.example.com"})
	if !changed {
		t.Fatal("expected config to change")
	}
	if !strings.Contains(out, "server_name example.com www.example.com;") {
		t.Errorf("server_name not extended:\n%s", out)
	}
}

func TestAddServerNameAliasesIdempotent(t *testing.T) {
	config := "server {\n    server_name example.com www.example.com;\n}\n"
	out, changed := AddServerNameAliases(config, "example.com", []string{"www.example.com"})
	if changed {
		t.Errorf("expected no change when alias already present, got:\n%s", out)
	}
	if out != config {
		t.Errorf("config should be unchanged, got:\n%s", out)
	}
}

func TestAddServerNameAliasesOnlyTouchesPrimaryBlocks(t *testing.T) {
	// Two server blocks; only the one serving the primary domain should gain the
	// alias. An unrelated block must be left alone.
	config := `server {
    server_name example.com;
}
server {
    server_name other.com;
}
`
	out, changed := AddServerNameAliases(config, "example.com", []string{"www.example.com"})
	if !changed {
		t.Fatal("expected change")
	}
	if !strings.Contains(out, "server_name example.com www.example.com;") {
		t.Errorf("primary block not extended:\n%s", out)
	}
	if !strings.Contains(out, "server_name other.com;") || strings.Contains(out, "other.com www.example.com") {
		t.Errorf("unrelated block was modified:\n%s", out)
	}
}

func TestAddServerNameAliasesMultipleBlocks(t *testing.T) {
	// A primary domain present in both the :80 and :443 blocks should be extended
	// in both so the cert and the authenticator agree.
	config := `server {
    listen 80;
    server_name example.com;
}
server {
    listen 443 ssl;
    server_name example.com;
}
`
	out, changed := AddServerNameAliases(config, "example.com", []string{"www.example.com"})
	if !changed {
		t.Fatal("expected change")
	}
	if got := strings.Count(out, "server_name example.com www.example.com;"); got != 2 {
		t.Errorf("expected both blocks extended, got %d:\n%s", got, out)
	}
}

func TestAddServerNameAliasesNoPrimaryMatch(t *testing.T) {
	config := "server {\n    server_name other.com;\n}\n"
	out, changed := AddServerNameAliases(config, "example.com", []string{"www.example.com"})
	if changed || out != config {
		t.Errorf("expected no change when primary absent, got changed=%v:\n%s", changed, out)
	}
}

func TestAddServerNameAliasesNoAliases(t *testing.T) {
	config := "server {\n    server_name example.com;\n}\n"
	if _, changed := AddServerNameAliases(config, "example.com", nil); changed {
		t.Error("expected no change with empty aliases")
	}
}

func TestAddServerNameAliasesQuotedNames(t *testing.T) {
	// Quoted server_name values must still be recognised and extended.
	config := "server {\n    server_name \"example.com\";\n}\n"
	out, changed := AddServerNameAliases(config, "example.com", []string{"www.example.com"})
	if !changed {
		t.Fatalf("expected quoted server_name to be extended:\n%s", out)
	}
	// Existing quoted token preserved; new alias appended unquoted.
	if !strings.Contains(out, "server_name \"example.com\" www.example.com;") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestAddServerNameAliasesQuotedIdempotent(t *testing.T) {
	config := "server {\n    server_name \"example.com\" www.example.com;\n}\n"
	if out, changed := AddServerNameAliases(config, "example.com", []string{"www.example.com"}); changed {
		t.Errorf("expected no change when alias already present (quoted primary):\n%s", out)
	}
}
