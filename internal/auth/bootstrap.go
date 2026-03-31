package auth

import (
	"context"
	"crypto/subtle"
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
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.username))
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.password))
	if usernameMatch != 1 || passwordMatch != 1 {
		return nil, ErrInvalidCredentials
	}

	return &Identity{
		Username:     username,
		DisplayName:  username,
		AuthProvider: "bootstrap",
	}, nil
}
