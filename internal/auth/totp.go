package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const totpPeriod = 30 * time.Second

func GenerateTOTPSecret() (string, error) {
	buffer := make([]byte, 20)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	return encoder.EncodeToString(buffer), nil
}

func BuildTOTPProvisioningURI(issuer string, account string, secret string) string {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	secret = strings.ToUpper(strings.TrimSpace(secret))
	label := url.PathEscape(firstNonEmpty(issuer, "Server Side Control") + ":" + account)
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", firstNonEmpty(issuer, "Server Side Control"))
	values.Set("algorithm", "SHA1")
	values.Set("digits", "6")
	values.Set("period", strconv.Itoa(int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func ValidateTOTP(secret string, code string, now time.Time) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	code = normalizeTOTPCode(code)
	if secret == "" || len(code) != 6 {
		return false
	}
	for offset := -1; offset <= 1; offset++ {
		if generateTOTP(secret, now.Add(time.Duration(offset)*totpPeriod)) == code {
			return true
		}
	}
	return false
}

func normalizeTOTPCode(code string) string {
	var builder strings.Builder
	for _, char := range code {
		if char >= '0' && char <= '9' {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func generateTOTP(secret string, at time.Time) string {
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := encoder.DecodeString(secret)
	if err != nil {
		return ""
	}
	counter := uint64(at.Unix()) / uint64(totpPeriod/time.Second)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", value%1000000)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}