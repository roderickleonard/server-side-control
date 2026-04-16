
//go:build linux

package auth

import (
	"context"
	"os/user"
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
	if err := authenticateWithPAM(a.serviceName, username, password); err != nil {
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
