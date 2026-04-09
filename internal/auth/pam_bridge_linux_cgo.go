//go:build linux && cgo

package auth

import (
	"fmt"

	pam "github.com/msteinert/pam/v2"
)

func authenticateWithPAM(serviceName string, username string, password string) error {
	tx, err := pam.StartFunc(serviceName, username, func(_ pam.Style, _ string) (string, error) {
		return password, nil
	})
	if err != nil {
		return fmt.Errorf("pam start: %w", err)
	}
	if err := tx.Authenticate(0); err != nil {
		return err
	}
	if err := tx.AcctMgmt(0); err != nil {
		return err
	}
	return nil
}
