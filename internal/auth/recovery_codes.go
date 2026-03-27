package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

var recoveryCodeAlphabet = []byte("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

func GenerateRecoveryCodes(count int) ([]string, []string, error) {
	if count <= 0 {
		count = 8
	}
	plain := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for index := 0; index < count; index++ {
		code, err := randomRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return plain, hashes, nil
}

func HashRecoveryCode(code string) string {
	normalized := normalizeRecoveryCode(code)
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func normalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}

func randomRecoveryCode() (string, error) {
	buffer := make([]byte, 10)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	result := make([]byte, 10)
	for index, value := range buffer {
		result[index] = recoveryCodeAlphabet[int(value)%len(recoveryCodeAlphabet)]
	}
	return string(result[:5]) + "-" + string(result[5:]), nil
}