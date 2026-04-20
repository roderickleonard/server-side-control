//go:build !linux

package system

import (
	"fmt"
	"io"
)

type stubSSHAccountManager struct{}

func NewSSHAccountManager() SSHAccountManager {
	return stubSSHAccountManager{}
}

func (stubSSHAccountManager) Inspect(username string) (SSHAccountStatus, error) {
	return SSHAccountStatus{}, fmt.Errorf("ssh account management is only supported on Linux target hosts")
}

func (stubSSHAccountManager) AddKey(spec SSHAddKeySpec) error {
	return fmt.Errorf("ssh account management is only supported on Linux target hosts")
}

func (stubSSHAccountManager) RemoveKey(spec SSHRemoveKeySpec) error {
	return fmt.Errorf("ssh account management is only supported on Linux target hosts")
}

func (stubSSHAccountManager) SetPassword(spec SSHPasswordSpec) error {
	return fmt.Errorf("ssh account management is only supported on Linux target hosts")
}

func StreamSSHAddKey(spec SSHAddKeySpec, stdout io.Writer) error {
	return fmt.Errorf("ssh account management is only supported on Linux target hosts")
}

func StreamSSHRemoveKey(spec SSHRemoveKeySpec, stdout io.Writer) error {
	return fmt.Errorf("ssh account management is only supported on Linux target hosts")
}
