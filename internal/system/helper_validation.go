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
	"nginx.apply_site": {},
	"nginx.delete_site": {},
	"nginx.validate":   {},
	"nginx.reload":     {},
	"nginx.enable_tls": {},
	"deploy.run":       {},
	"deploy.rollback":  {},
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
