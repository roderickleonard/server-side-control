package auth

import (
	"context"
	"errors"
)

type ChainAuthenticator struct {
	authenticators []Authenticator
}

func NewChainAuthenticator(authenticators ...Authenticator) *ChainAuthenticator {
	return &ChainAuthenticator{authenticators: authenticators}
}

func (a *ChainAuthenticator) Authenticate(ctx context.Context, username string, password string) (*Identity, error) {
	var unsupported bool
	for _, authenticator := range a.authenticators {
		identity, err := authenticator.Authenticate(ctx, username, password)
		if err == nil {
			return identity, nil
		}
		if errors.Is(err, ErrUnsupported) {
			unsupported = true
			continue
		}
		if errors.Is(err, ErrInvalidCredentials) {
			continue
		}
		return nil, err
	}

	if unsupported {
		return nil, ErrUnsupported
	}

	return nil, ErrInvalidCredentials
}
