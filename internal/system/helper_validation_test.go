package system

import "testing"

func TestValidateHelperAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		wantErr bool
	}{
		{name: "allowed deploy rollback", action: "deploy.rollback", wantErr: false},
		{name: "allowed deploy inspect", action: "deploy.inspect", wantErr: false},
		{name: "allowed runtime inspect", action: "runtime.inspect", wantErr: false},
		{name: "allowed git auth", action: "git_auth.ensure_deploy_key", wantErr: false},
		{name: "allowed mysql provisioning", action: "mysql.provision_database", wantErr: false},
		{name: "allowed mysql admin password rotation", action: "mysql.rotate_admin_password", wantErr: false},
		{name: "allowed tls", action: "nginx.enable_tls", wantErr: false},
		{name: "allowed site delete", action: "nginx.delete_site", wantErr: false},
		{name: "allowed php version listing", action: "php.list_versions", wantErr: false},
		{name: "blocked arbitrary shell", action: "shell.exec", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateHelperAction(test.action)
			if test.wantErr && err == nil {
				t.Fatalf("expected error for action %q", test.action)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("did not expect error for action %q: %v", test.action, err)
			}
		})
	}
}
