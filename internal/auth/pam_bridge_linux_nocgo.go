//go:build linux && !cgo

package auth

func authenticateWithPAM(serviceName string, username string, password string) error {
	return ErrUnsupported
}
