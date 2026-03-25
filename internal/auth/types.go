package auth

import "context"

type Identity struct {
	Username     string
	DisplayName  string
	AuthProvider string
}

type Authenticator interface {
	Authenticate(ctx context.Context, username string, password string) (*Identity, error)
}
