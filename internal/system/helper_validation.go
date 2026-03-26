package system

import "errors"

const MaxHelperPayloadBytes = 1 << 20

var ErrHelperActionNotAllowed = errors.New("helper action not allowed")

var allowedHelperActions = map[string]struct{}{
	"user.create":      {},
	"user.list":        {},
	"user.delete":      {},
	"mysql.provision_database": {},
	"mysql.list_access": {},
	"mysql.delete_access": {},
	"mysql.rotate_user_password": {},
	"mysql.rotate_admin_password": {},
	"mysql.inspect_database": {},
	"mysql.restore_database": {},
	"nginx.apply_site": {},
	"nginx.delete_site": {},
	"nginx.validate":   {},
	"nginx.reload":     {},
	"nginx.enable_tls": {},
	"deploy.run":       {},
	"deploy.rollback":  {},
	"deploy.inspect":   {},
	"runtime.inspect":  {},
	"runtime.install_nvm": {},
	"runtime.install_node": {},
	"runtime.install_pm2": {},
	"runtime.start_pm2": {},
	"runtime.run_npm_script": {},
	"runtime.run_npm_install": {},
	"runtime.run_custom_command": {},
	"panel.write_env":   {},
	"panel.apply_proxy": {},
	"panel.restart_service": {},
	"panel.inspect_tls": {},
	"files.write_env":  {},
	"files.read_env":   {},
	"files.read_text":  {},
	"files.list_dir":   {},
	"git_auth.inspect": {},
	"git_auth.ensure_deploy_key": {},
	"git_auth.trust_host": {},
	"git_auth.store_credential": {},
	"pm2.list":         {},
	"pm2.restart":      {},
	"pm2.reload":       {},
	"pm2.start":        {},
	"pm2.stop":         {},
	"pm2.logs":         {},
	"php.switch":       {},
	"php.list_versions": {},
}

func ValidateHelperAction(action string) error {
	if _, ok := allowedHelperActions[action]; !ok {
		return ErrHelperActionNotAllowed
	}
	return nil
}
