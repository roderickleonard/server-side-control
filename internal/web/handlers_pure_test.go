package web

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// panelDomainFromBaseURL
// ---------------------------------------------------------------------------

func TestPanelDomainFromBaseURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"http plain domain", "http://example.com", "example.com"},
		{"https with port", "https://panel.example.com:8080", "panel.example.com"},
		{"IPv4 address returns empty", "http://192.168.1.1", ""},
		{"IPv6 address returns empty", "http://[::1]:8080", ""},
		{"invalid URL returns empty", "://not a url", ""},
		{"empty string returns empty", "", ""},
		{"no scheme just host", "example.com", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := panelDomainFromBaseURL(tc.input)
			if got != tc.want {
				t.Errorf("panelDomainFromBaseURL(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// siteDetailTabForAction
// ---------------------------------------------------------------------------

func TestSiteDetailTabForAction(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"sync_repository", "deploy"},
		{"generate_deploy_key", "deploy"},
		{"trust_git_host", "deploy"},
		{"save_auto_deploy", "deploy"},
		{"rotate_auto_deploy_secret", "deploy"},
		{"run_custom_git_command", "deploy"},
		{"run_ssh_command", "ssh"},
		{"add_ssh_key", "ssh"},
		{"remove_ssh_key", "ssh"},
		{"set_ssh_password", "ssh"},
		{"install_nvm", "runtime"},
		{"install_node", "runtime"},
		{"install_pm2", "runtime"},
		{"run_npm_script", "runtime"},
		{"enable_tls", "domains"},
		{"add_subdomain", "domains"},
		{"delete_subdomain", "domains"},
		{"enable_subdomain_tls", "domains"},
		{"sync_subdomain_repository", "domains"},
		{"save_site_file", "files"},
		{"create_site_file", "files"},
		{"chmod_site_file", "files"},
		{"assign_database", "settings"},
		{"assign_linux_user", "settings"},
		{"edit_env", "settings"},
		{"save_nginx_config", "settings"},
		{"create_cron_job", "settings"},
		{"save_backup_config", "backups"},
		{"run_backup_now", "backups"},
		{"select_dns_zone", "dns"},
		{"create_dns_record", "dns"},
		{"update_dns_record", "dns"},
		{"delete_dns_record", "dns"},
		{"unknown_action", "overview"},
		{"", "overview"},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := siteDetailTabForAction(tc.action)
			if got != tc.want {
				t.Errorf("siteDetailTabForAction(%q) = %q; want %q", tc.action, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// subdomainDetailTabForAction
// ---------------------------------------------------------------------------

func TestSubdomainDetailTabForAction(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"sync_subdomain_repository", "deploy"},
		{"run_subdomain_git_command", "deploy"},
		{"save_subdomain_deploy", "deploy"},
		{"rotate_subdomain_auto_deploy_secret", "deploy"},
		{"rollback_subdomain_release", "deploy"},
		{"generate_subdomain_deploy_key", "deploy"},
		{"trust_subdomain_git_host", "deploy"},
		{"install_nvm", "runtime"},
		{"install_node", "runtime"},
		{"npm_install", "runtime"},
		{"run_npm_script", "runtime"},
		{"save_subdomain_file", "files"},
		{"create_subdomain_file", "files"},
		{"delete_subdomain", "settings"},
		{"enable_subdomain_tls", "settings"},
		{"save_nginx_config", "settings"},
		{"edit_subdomain_env", "settings"},
		{"unknown", "overview"},
		{"", "overview"},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := subdomainDetailTabForAction(tc.action)
			if got != tc.want {
				t.Errorf("subdomainDetailTabForAction(%q) = %q; want %q", tc.action, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// autoDeployCommandFromPreset
// ---------------------------------------------------------------------------

func TestAutoDeployCommandFromPreset(t *testing.T) {
	tests := []struct {
		name        string
		preset      string
		processName string
		fallback    string
		want        string
	}{
		{
			name:        "pm2_restart with process name",
			preset:      "pm2_restart",
			processName: "myapp",
			fallback:    "fallback-cmd",
			want:        "pm2 restart 'myapp'",
		},
		{
			name:        "pm2_restart empty process name returns fallback",
			preset:      "pm2_restart",
			processName: "",
			fallback:    "fallback-cmd",
			want:        "fallback-cmd",
		},
		{
			name:        "pm2_restart whitespace process name returns fallback",
			preset:      "pm2_restart",
			processName: "   ",
			fallback:    "fallback-cmd",
			want:        "fallback-cmd",
		},
		{
			name:        "pm2_reload with process name",
			preset:      "pm2_reload",
			processName: "myapp",
			fallback:    "fallback-cmd",
			want:        "pm2 reload 'myapp'",
		},
		{
			name:        "pm2_reload empty process name returns fallback",
			preset:      "pm2_reload",
			processName: "",
			fallback:    "fallback-cmd",
			want:        "fallback-cmd",
		},
		{
			name:        "custom preset returns fallback",
			preset:      "custom",
			processName: "myapp",
			fallback:    "fallback-cmd",
			want:        "fallback-cmd",
		},
		{
			name:        "unknown preset returns fallback",
			preset:      "unknown_preset",
			processName: "myapp",
			fallback:    "fallback-cmd",
			want:        "fallback-cmd",
		},
		{
			name:        "empty preset returns fallback",
			preset:      "",
			processName: "myapp",
			fallback:    "fallback-cmd",
			want:        "fallback-cmd",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := autoDeployCommandFromPreset(tc.preset, tc.processName, tc.fallback)
			if got != tc.want {
				t.Errorf("autoDeployCommandFromPreset(%q, %q, %q) = %q; want %q",
					tc.preset, tc.processName, tc.fallback, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectAutoDeployPreset
// ---------------------------------------------------------------------------

func TestDetectAutoDeployPreset(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantPreset  string
		wantProcess string
	}{
		{
			name:        "pm2 restart with quoted name",
			command:     "pm2 restart 'myapp'",
			wantPreset:  "pm2_restart",
			wantProcess: "myapp",
		},
		{
			name:        "pm2 reload with quoted name",
			command:     "pm2 reload 'myapp'",
			wantPreset:  "pm2_reload",
			wantProcess: "myapp",
		},
		{
			name:        "pm2 restart without quotes",
			command:     "pm2 restart myapp",
			wantPreset:  "pm2_restart",
			wantProcess: "myapp",
		},
		{
			name:        "empty command returns custom",
			command:     "",
			wantPreset:  "custom",
			wantProcess: "",
		},
		{
			name:        "whitespace only returns custom",
			command:     "   ",
			wantPreset:  "custom",
			wantProcess: "",
		},
		{
			name:        "arbitrary command returns custom",
			command:     "npm run start",
			wantPreset:  "custom",
			wantProcess: "",
		},
		{
			name:        "pm2 restart with no process name returns custom",
			command:     "pm2 restart ",
			wantPreset:  "custom",
			wantProcess: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPreset, gotProcess := detectAutoDeployPreset(tc.command)
			if gotPreset != tc.wantPreset || gotProcess != tc.wantProcess {
				t.Errorf("detectAutoDeployPreset(%q) = (%q, %q); want (%q, %q)",
					tc.command, gotPreset, gotProcess, tc.wantPreset, tc.wantProcess)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validNodeVersionSelection
// ---------------------------------------------------------------------------

func TestValidNodeVersionSelection(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"", true},
		{"18", true},
		{"18.17.1", true},
		{"v18", true},
		{"lts/*", true},
		{"lts/hydrogen", true},
		{"node", true},
		{"20.0.0", true},
		{"v20.0.0", true},
		{"lts/fermium", true},
		{"invalid version!", false},
		{"18 19", false},
		{"18.17.1.0", false},
		{"latest", false},
		{"^18", false},
		{">=18", false},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			got := validNodeVersionSelection(tc.value)
			if got != tc.want {
				t.Errorf("validNodeVersionSelection(%q) = %v; want %v", tc.value, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mergeNodeVersionOptions
// ---------------------------------------------------------------------------

func TestMergeNodeVersionOptions(t *testing.T) {
	t.Run("deduplicates versions", func(t *testing.T) {
		got := mergeNodeVersionOptions([]string{"18", "20"}, []string{"18", "22"})
		want := []string{"18", "20", "22"}
		if len(got) != len(want) {
			t.Fatalf("got %v; want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d: got %q; want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("skips empty strings", func(t *testing.T) {
		got := mergeNodeVersionOptions([]string{"", "18", ""})
		if len(got) != 1 || got[0] != "18" {
			t.Errorf("got %v; want [18]", got)
		}
	})

	t.Run("skips invalid versions", func(t *testing.T) {
		got := mergeNodeVersionOptions([]string{"18", "invalid version!", "20"})
		want := []string{"18", "20"}
		if len(got) != len(want) {
			t.Fatalf("got %v; want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d: got %q; want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("preserves order of first occurrence", func(t *testing.T) {
		got := mergeNodeVersionOptions(
			[]string{"20", "18", "lts/*"},
			[]string{"18", "22"},
		)
		want := []string{"20", "18", "lts/*", "22"}
		if len(got) != len(want) {
			t.Fatalf("got %v; want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d: got %q; want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("no groups returns empty slice", func(t *testing.T) {
		got := mergeNodeVersionOptions()
		if len(got) != 0 {
			t.Errorf("got %v; want []", got)
		}
	})

	t.Run("trims whitespace before validation", func(t *testing.T) {
		got := mergeNodeVersionOptions([]string{"  18  ", " 20 "})
		want := []string{"18", "20"}
		if len(got) != len(want) {
			t.Fatalf("got %v; want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d: got %q; want %q", i, got[i], want[i])
			}
		}
	})
}

// ---------------------------------------------------------------------------
// humanizeDuration
// ---------------------------------------------------------------------------

func TestHumanizeDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{"30 seconds is under 1 minute", 30 * time.Second, "under 1 minute"},
		{"0 duration is under 1 minute", 0, "under 1 minute"},
		{"59 seconds is under 1 minute", 59 * time.Second, "under 1 minute"},
		{"5 minutes", 5 * time.Minute, "5m"},
		{"1 hour", 1 * time.Hour, "1h"},
		{"90 minutes", 90 * time.Minute, "1h 30m"},
		{"25 hours", 25 * time.Hour, "1d 1h"},
		{"1 day 2h 30m", 1*24*time.Hour + 2*time.Hour + 30*time.Minute, "1d 2h 30m"},
		{"exactly 1 day", 24 * time.Hour, "1d"},
		{"2 days", 48 * time.Hour, "2d"},
		{"1 minute", 1 * time.Minute, "1m"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := humanizeDuration(tc.duration)
			if got != tc.want {
				t.Errorf("humanizeDuration(%v) = %q; want %q", tc.duration, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeCronFields
// ---------------------------------------------------------------------------

func TestNormalizeCronFields(t *testing.T) {
	tests := []struct {
		name     string
		schedule string
		want     []string
		wantErr  bool
	}{
		{
			name:     "@daily",
			schedule: "@daily",
			want:     []string{"0", "0", "*", "*", "*"},
		},
		{
			name:     "@midnight alias for @daily",
			schedule: "@midnight",
			want:     []string{"0", "0", "*", "*", "*"},
		},
		{
			name:     "@hourly",
			schedule: "@hourly",
			want:     []string{"0", "*", "*", "*", "*"},
		},
		{
			name:     "@weekly",
			schedule: "@weekly",
			want:     []string{"0", "0", "*", "*", "0"},
		},
		{
			name:     "@monthly",
			schedule: "@monthly",
			want:     []string{"0", "0", "1", "*", "*"},
		},
		{
			name:     "@yearly",
			schedule: "@yearly",
			want:     []string{"0", "0", "1", "1", "*"},
		},
		{
			name:     "@annually alias for @yearly",
			schedule: "@annually",
			want:     []string{"0", "0", "1", "1", "*"},
		},
		{
			name:     "@reboot returns error",
			schedule: "@reboot",
			wantErr:  true,
		},
		{
			name:     "five field wildcard",
			schedule: "* * * * *",
			want:     []string{"*", "*", "*", "*", "*"},
		},
		{
			name:     "specific schedule",
			schedule: "0 12 * * 1",
			want:     []string{"0", "12", "*", "*", "1"},
		},
		{
			name:     "complex schedule",
			schedule: "*/15 9-17 * * 1-5",
			want:     []string{"*/15", "9-17", "*", "*", "1-5"},
		},
		{
			name:     "invalid — fewer than 5 fields",
			schedule: "invalid",
			wantErr:  true,
		},
		{
			name:     "invalid — too many fields",
			schedule: "* * * * * *",
			wantErr:  true,
		},
		{
			name:     "case insensitive macro",
			schedule: "@Daily",
			want:     []string{"0", "0", "*", "*", "*"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeCronFields(tc.schedule)
			if tc.wantErr {
				if err == nil {
					t.Errorf("normalizeCronFields(%q): expected error, got nil", tc.schedule)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeCronFields(%q): unexpected error: %v", tc.schedule, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeCronFields(%q) = %v; want %v", tc.schedule, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("normalizeCronFields(%q)[%d] = %q; want %q", tc.schedule, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cronFieldMatches
// ---------------------------------------------------------------------------

func TestCronFieldMatches(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		value      int
		fieldIndex int
		want       bool
	}{
		// Wildcard
		{"wildcard matches any minute", "*", 0, 0, true},
		{"wildcard matches max minute", "*", 59, 0, true},
		// Exact value
		{"exact 5 matches 5", "5", 5, 0, true},
		{"exact 5 does not match 6", "5", 6, 0, false},
		// Range
		{"range 0-5 matches 0", "0-5", 0, 0, true},
		{"range 0-5 matches 3", "0-5", 3, 0, true},
		{"range 0-5 matches 5", "0-5", 5, 0, true},
		{"range 0-5 does not match 6", "0-5", 6, 0, false},
		// Step on wildcard (fieldIndex=0 → minutes, bounds 0-59)
		{"*/15 matches 0", "*/15", 0, 0, true},
		{"*/15 matches 15", "*/15", 15, 0, true},
		{"*/15 matches 30", "*/15", 30, 0, true},
		{"*/15 matches 45", "*/15", 45, 0, true},
		{"*/15 does not match 7", "*/15", 7, 0, false},
		// List
		{"list 1,3,5 matches 1", "1,3,5", 1, 0, true},
		{"list 1,3,5 matches 3", "1,3,5", 3, 0, true},
		{"list 1,3,5 matches 5", "1,3,5", 5, 0, true},
		{"list 1,3,5 does not match 2", "1,3,5", 2, 0, false},
		// Range with step
		{"0-30/10 matches 0", "0-30/10", 0, 0, true},
		{"0-30/10 matches 10", "0-30/10", 10, 0, true},
		{"0-30/10 matches 20", "0-30/10", 20, 0, true},
		{"0-30/10 matches 30", "0-30/10", 30, 0, true},
		{"0-30/10 does not match 5", "0-30/10", 5, 0, false},
		{"0-30/10 does not match 35", "0-30/10", 35, 0, false},
		// Day of week (fieldIndex=4)
		{"dow 7 matches Sunday (0) special case", "7", 0, 4, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cronFieldMatches(tc.expression, tc.value, tc.fieldIndex)
			if got != tc.want {
				t.Errorf("cronFieldMatches(%q, %d, %d) = %v; want %v",
					tc.expression, tc.value, tc.fieldIndex, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cronDayMatches
// ---------------------------------------------------------------------------

func TestCronDayMatches(t *testing.T) {
	tests := []struct {
		name          string
		domExpr       string
		dowExpr       string
		domMatches    bool
		dowMatches    bool
		want          bool
	}{
		// Both wildcards → always true regardless of match booleans.
		{"both wildcards dom-match=false dow-match=false", "*", "*", false, false, true},
		{"both wildcards dom-match=true dow-match=true", "*", "*", true, true, true},
		// DOM wildcard → use dowMatches.
		{"dom wildcard dow-match=true", "*", "1", false, true, true},
		{"dom wildcard dow-match=false", "*", "1", true, false, false},
		// DOW wildcard → use domMatches.
		{"dow wildcard dom-match=true", "15", "*", true, false, true},
		{"dow wildcard dom-match=false", "15", "*", false, true, false},
		// Neither wildcard → OR.
		{"neither wildcard both false", "15", "1", false, false, false},
		{"neither wildcard dom true", "15", "1", true, false, true},
		{"neither wildcard dow true", "15", "1", false, true, true},
		{"neither wildcard both true", "15", "1", true, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cronDayMatches(tc.domExpr, tc.dowExpr, tc.domMatches, tc.dowMatches)
			if got != tc.want {
				t.Errorf("cronDayMatches(%q, %q, %v, %v) = %v; want %v",
					tc.domExpr, tc.dowExpr, tc.domMatches, tc.dowMatches, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isAllowedNginxConfigPath
// ---------------------------------------------------------------------------

func TestIsAllowedNginxConfigPath(t *testing.T) {
	tests := []struct {
		name       string
		baseDir    string
		configPath string
		want       bool
	}{
		{
			name:       "config inside base dir",
			baseDir:    "/etc/nginx/sites-available",
			configPath: "/etc/nginx/sites-available/mysite",
			want:       true,
		},
		{
			name:       "config equal to base dir",
			baseDir:    "/etc/nginx/sites-available",
			configPath: "/etc/nginx/sites-available",
			want:       true,
		},
		{
			name:       "config outside base dir",
			baseDir:    "/etc/nginx/sites-available",
			configPath: "/etc/nginx/sites-enabled/mysite",
			want:       false,
		},
		{
			name:       "path traversal blocked",
			baseDir:    "/etc/nginx/sites-available",
			configPath: "/etc/nginx/sites-available/../sites-enabled/mysite",
			want:       false,
		},
		{
			name:       "relative base dir rejected",
			baseDir:    "etc/nginx/sites-available",
			configPath: "/etc/nginx/sites-available/mysite",
			want:       false,
		},
		{
			name:       "relative config path rejected",
			baseDir:    "/etc/nginx/sites-available",
			configPath: "etc/nginx/sites-available/mysite",
			want:       false,
		},
		{
			name:       "both relative rejected",
			baseDir:    "sites-available",
			configPath: "sites-available/mysite",
			want:       false,
		},
		{
			name:       "empty base dir rejected",
			baseDir:    "",
			configPath: "/etc/nginx/sites-available/mysite",
			want:       false,
		},
		{
			name:       "empty config path rejected",
			baseDir:    "/etc/nginx/sites-available",
			configPath: "",
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isAllowedNginxConfigPath(tc.baseDir, tc.configPath)
			if got != tc.want {
				t.Errorf("isAllowedNginxConfigPath(%q, %q) = %v; want %v",
					tc.baseDir, tc.configPath, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// resolveSiteBrowserPath
// ---------------------------------------------------------------------------

func TestResolveSiteBrowserPath(t *testing.T) {
	tests := []struct {
		name      string
		rootDir   string
		requested string
		wantAbs   string
		wantRel   string
		wantErr   bool
	}{
		{
			name:      "empty requested returns root",
			rootDir:   "/var/www/mysite",
			requested: "",
			wantAbs:   "/var/www/mysite",
			wantRel:   "",
		},
		{
			name:      "single dir requested",
			rootDir:   "/var/www/mysite",
			requested: "public",
			wantAbs:   "/var/www/mysite/public",
			wantRel:   "public",
		},
		{
			name:      "nested file requested",
			rootDir:   "/var/www/mysite",
			requested: "public/index.php",
			wantAbs:   "/var/www/mysite/public/index.php",
			wantRel:   "public/index.php",
		},
		{
			// filepath.Clean("/"+requested) normalises "/../etc/passwd" to "/etc/passwd",
			// so the relative path becomes "etc/passwd" which is still inside the root.
			// True traversal requires an absolute path that escapes after join, e.g. a
			// symlink-free test. The function neutralises dotdot via the leading "/" trick,
			// so this input is actually allowed (resolves to rootDir/etc/passwd).
			name:      "dotdot requested is neutralised — resolves inside root",
			rootDir:   "/var/www/mysite",
			requested: "../etc/passwd",
			wantAbs:   "/var/www/mysite/etc/passwd",
			wantRel:   "etc/passwd",
		},
		{
			name:      "relative rootDir returns error",
			rootDir:   "var/www/mysite",
			requested: "",
			wantErr:   true,
		},
		{
			name:      "empty rootDir returns error",
			rootDir:   "",
			requested: "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAbs, gotRel, err := resolveSiteBrowserPath(tc.rootDir, tc.requested)
			if tc.wantErr {
				if err == nil {
					t.Errorf("resolveSiteBrowserPath(%q, %q): expected error, got nil (abs=%q, rel=%q)",
						tc.rootDir, tc.requested, gotAbs, gotRel)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSiteBrowserPath(%q, %q): unexpected error: %v",
					tc.rootDir, tc.requested, err)
			}
			if gotAbs != tc.wantAbs {
				t.Errorf("abs: got %q; want %q", gotAbs, tc.wantAbs)
			}
			if gotRel != tc.wantRel {
				t.Errorf("rel: got %q; want %q", gotRel, tc.wantRel)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parentRelativePath
// ---------------------------------------------------------------------------

func TestParentRelativePath(t *testing.T) {
	tests := []struct {
		relPath string
		want    string
	}{
		{"", ""},
		{"file.php", ""},
		{"public/index.php", "public"},
		{"a/b/c.php", "a/b"},
		{"a/b/c/d.php", "a/b/c"},
		{"singledir", ""},
	}

	for _, tc := range tests {
		t.Run(tc.relPath, func(t *testing.T) {
			got := parentRelativePath(tc.relPath)
			if got != tc.want {
				t.Errorf("parentRelativePath(%q) = %q; want %q", tc.relPath, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildAutoDeployWebhookURL
// ---------------------------------------------------------------------------

func TestBuildAutoDeployWebhookURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		siteName string
		secret   string
		wantURL  string
		wantFn   func(t *testing.T, got string)
	}{
		{
			name:     "empty baseURL returns empty",
			baseURL:  "",
			siteName: "mysite",
			secret:   "s3cr3t",
			wantURL:  "",
		},
		{
			name:     "empty siteName returns empty",
			baseURL:  "https://panel.example.com",
			siteName: "",
			secret:   "s3cr3t",
			wantURL:  "",
		},
		{
			name:     "empty secret returns empty",
			baseURL:  "https://panel.example.com",
			siteName: "mysite",
			secret:   "",
			wantURL:  "",
		},
		{
			name:     "all provided produces webhook URL",
			baseURL:  "https://panel.example.com",
			siteName: "mysite",
			secret:   "s3cr3t",
			wantFn: func(t *testing.T, got string) {
				t.Helper()
				const wantPath = "/webhooks/site-deploy"
				if got == "" {
					t.Fatal("got empty URL")
				}
				// Must contain the path and both query params.
				for _, substr := range []string{wantPath, "secret=s3cr3t", "site=mysite"} {
					found := false
					for i := 0; i <= len(got)-len(substr); i++ {
						if got[i:i+len(substr)] == substr {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("buildAutoDeployWebhookURL result %q missing %q", got, substr)
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildAutoDeployWebhookURL(tc.baseURL, tc.siteName, tc.secret)
			if tc.wantFn != nil {
				tc.wantFn(t, got)
				return
			}
			if got != tc.wantURL {
				t.Errorf("buildAutoDeployWebhookURL(%q, %q, %q) = %q; want %q",
					tc.baseURL, tc.siteName, tc.secret, got, tc.wantURL)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildWebhookBranch
// ---------------------------------------------------------------------------

func TestBuildWebhookBranch(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "refs/heads/main extracts main",
			payload: `{"ref": "refs/heads/main"}`,
			want:    "main",
		},
		{
			name:    "refs/heads/feature/foo extracts feature/foo",
			payload: `{"ref": "refs/heads/feature/foo"}`,
			want:    "feature/foo",
		},
		{
			name:    "empty ref returns empty",
			payload: `{"ref": ""}`,
			want:    "",
		},
		{
			name:    "invalid JSON returns empty",
			payload: `not json`,
			want:    "",
		},
		{
			name:    "missing ref field returns empty",
			payload: `{"other": "value"}`,
			want:    "",
		},
		{
			name:    "empty payload returns empty",
			payload: ``,
			want:    "",
		},
		{
			name:    "ref without refs/heads prefix returned as-is (trimmed)",
			payload: `{"ref": "main"}`,
			want:    "main",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildWebhookBranch([]byte(tc.payload))
			if got != tc.want {
				t.Errorf("buildWebhookBranch(%q) = %q; want %q", tc.payload, got, tc.want)
			}
		})
	}
}
