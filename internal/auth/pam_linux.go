//go:build linux

package auth

import (
	"context"
	"fmt"
	"os/user"

	pam "github.com/msteinert/pam/v2"
)

type PAMAuthenticator struct {
	serviceName string
}

func NewPAMAuthenticator(serviceName string) *PAMAuthenticator {
	if serviceName == "" {
		serviceName = "login"
	}
	return &PAMAuthenticator{serviceName: serviceName}
}

func (a *PAMAuthenticator) Authenticate(_ context.Context, username string, password string) (*Identity, error) {
	tx, err := pam.StartFunc(a.serviceName, username, func(_ pam.Style, _ string) (string, error) {
		return password, nil
	})
	if err != nil {
		return nil, fmt.Errorf("pam start: %w", err)
	}

	if err := tx.Authenticate(0); err != nil {
		return nil, ErrInvalidCredentials
	}
	if err := tx.AcctMgmt(0); err != nil {
		return nil, ErrInvalidCredentials
	}

	displayName := username
	if linuxUser, err := user.Lookup(username); err == nil && linuxUser.Name != "" {
		displayName = linuxUser.Name
	}

	return &Identity{
		Username:     username,
		DisplayName:  displayName,
		AuthProvider: "pam",
	}, nil
}
