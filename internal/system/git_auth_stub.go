//go:build !linux

package system

import (
	"fmt"
	"io"
)

type stubGitAuthManager struct{}

func NewGitAuthManager() GitAuthManager {
	return stubGitAuthManager{}
}

func (stubGitAuthManager) Inspect(spec GitAuthInspectSpec) (GitAuthStatus, error) {
	return GitAuthStatus{}, fmt.Errorf("git auth management is only supported on Ubuntu target hosts")
}

func (stubGitAuthManager) EnsureDeployKey(spec GitDeployKeySpec) (GitAuthStatus, string, error) {
	return GitAuthStatus{}, "", fmt.Errorf("git auth management is only supported on Ubuntu target hosts")
}

func (stubGitAuthManager) TrustHost(spec GitHostTrustSpec) (string, error) {
	return "", fmt.Errorf("git auth management is only supported on Ubuntu target hosts")
}

func (stubGitAuthManager) StoreCredential(spec GitCredentialSpec) (string, error) {
	return "", fmt.Errorf("git auth management is only supported on Ubuntu target hosts")
}

func StreamEnsureDeployKey(spec GitDeployKeySpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("git auth management is only supported on Ubuntu target hosts")
}

func StreamTrustGitHost(spec GitHostTrustSpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("git auth management is only supported on Ubuntu target hosts")
}

func StreamStoreGitCredential(spec GitCredentialSpec, stdout io.Writer, stderr io.Writer) error {
	return fmt.Errorf("git auth management is only supported on Ubuntu target hosts")
}