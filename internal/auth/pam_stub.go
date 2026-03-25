//go:build !linux

package auth

import "context"

type PAMAuthenticator struct{}

func NewPAMAuthenticator(_ string) *PAMAuthenticator {
	return &PAMAuthenticator{}
}

func (a *PAMAuthenticator) Authenticate(_ context.Context, _ string, _ string) (*Identity, error) {
	return nil, ErrUnsupported
}
