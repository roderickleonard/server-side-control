package auth

import (
	"context"
	"errors"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrUnsupported = errors.New("authentication backend unsupported on this host")

type BootstrapAuthenticator struct {
	username string
	password string
}

func NewBootstrapAuthenticator(username string, password string) *BootstrapAuthenticator {
	return &BootstrapAuthenticator{username: username, password: password}
}

func (a *BootstrapAuthenticator) Authenticate(_ context.Context, username string, password string) (*Identity, error) {
	if username != a.username || password != a.password {
		return nil, ErrInvalidCredentials
	}

	return &Identity{
		Username:     username,
		DisplayName:  username,
		AuthProvider: "bootstrap",
	}, nil
}
