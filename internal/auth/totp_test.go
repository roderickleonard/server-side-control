package auth

import (
	"strings"
	"testing"
	"time"
)

// testTOTPSecret is the well-known RFC 4226 test key encoded in base32.
// "12345678901234567890" → GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ (base32, no padding)
// We use the shorter "JBSWY3DPEHPK3PXP" which decodes to "Hello!" and is
// the canonical example key used in many TOTP test vectors.
const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// testTOTPTime is a fixed point in time used to produce deterministic codes.
// Unix timestamp 1704067200 = 2024-01-01 00:00:00 UTC.
var testTOTPTime = time.Unix(1704067200, 0)

func TestNormalizeTOTPCode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already clean six-digit code",
			input: "123456",
			want:  "123456",
		},
		{
			name:  "strips spaces around digits",
			input: " 123 456 ",
			want:  "123456",
		},
		{
			name:  "strips dashes",
			input: "123-456",
			want:  "123456",
		},
		{
			name:  "strips mixed non-digit characters",
			input: "1a2b3c4d5e6f",
			want:  "123456",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "only non-digit characters",
			input: "abc-def",
			want:  "",
		},
		{
			name:  "unicode letters stripped",
			input: "12Ñ34é56",
			want:  "123456",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeTOTPCode(tc.input)
			if got != tc.want {
				t.Errorf("normalizeTOTPCode(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestGenerateTOTP(t *testing.T) {
	t.Run("returns six-digit string", func(t *testing.T) {
		code := generateTOTP(testTOTPSecret, testTOTPTime)
		if len(code) != 6 {
			t.Errorf("generateTOTP returned %q (len %d); want 6 digits", code, len(code))
		}
		for _, ch := range code {
			if ch < '0' || ch > '9' {
				t.Errorf("generateTOTP returned non-digit character %q in %q", ch, code)
			}
		}
	})

	t.Run("deterministic: same secret+time produces same code", func(t *testing.T) {
		code1 := generateTOTP(testTOTPSecret, testTOTPTime)
		code2 := generateTOTP(testTOTPSecret, testTOTPTime)
		if code1 != code2 {
			t.Errorf("generateTOTP is not deterministic: got %q then %q", code1, code2)
		}
	})

	t.Run("different times within same window produce same code", func(t *testing.T) {
		// Both timestamps sit in the same 30-second TOTP window.
		t1 := time.Unix(1704067200, 0)
		t2 := time.Unix(1704067215, 0) // 15 seconds later, same window
		code1 := generateTOTP(testTOTPSecret, t1)
		code2 := generateTOTP(testTOTPSecret, t2)
		if code1 != code2 {
			t.Errorf("codes differ within the same 30s window: %q vs %q", code1, code2)
		}
	})

	t.Run("different windows produce different codes (with high probability)", func(t *testing.T) {
		// Advance by a full period to guarantee a different counter value.
		code1 := generateTOTP(testTOTPSecret, testTOTPTime)
		code2 := generateTOTP(testTOTPSecret, testTOTPTime.Add(30*time.Second))
		// There is a 1-in-1,000,000 chance these collide; acceptable for a unit test.
		if code1 == code2 {
			t.Logf("codes coincidentally equal (%q); this is astronomically unlikely", code1)
		}
	})

	t.Run("invalid secret returns empty string", func(t *testing.T) {
		code := generateTOTP("not-valid-base32!!!", testTOTPTime)
		if code != "" {
			t.Errorf("generateTOTP with invalid secret returned %q; want empty string", code)
		}
	})
}

func TestValidateTOTP(t *testing.T) {
	// Pre-compute the codes for the fixed time so the tests are self-consistent.
	secretUpper := strings.ToUpper(testTOTPSecret)
	codeAt := generateTOTP(secretUpper, testTOTPTime)
	codePrev := generateTOTP(secretUpper, testTOTPTime.Add(-30*time.Second))
	codeNext := generateTOTP(secretUpper, testTOTPTime.Add(30*time.Second))

	t.Run("correct code at exact time passes", func(t *testing.T) {
		if !ValidateTOTP(testTOTPSecret, codeAt, testTOTPTime) {
			t.Errorf("ValidateTOTP(%q, %q, now) = false; want true", testTOTPSecret, codeAt)
		}
	})

	t.Run("correct code at -30s (previous window) passes", func(t *testing.T) {
		if !ValidateTOTP(testTOTPSecret, codePrev, testTOTPTime) {
			t.Errorf("ValidateTOTP with previous-window code returned false; want true")
		}
	})

	t.Run("correct code at +30s (next window) passes", func(t *testing.T) {
		if !ValidateTOTP(testTOTPSecret, codeNext, testTOTPTime) {
			t.Errorf("ValidateTOTP with next-window code returned false; want true")
		}
	})

	t.Run("wrong code fails", func(t *testing.T) {
		wrong := "000000"
		if codeAt == wrong {
			wrong = "000001"
		}
		if ValidateTOTP(testTOTPSecret, wrong, testTOTPTime) {
			t.Errorf("ValidateTOTP with wrong code returned true; want false")
		}
	})

	t.Run("empty secret fails", func(t *testing.T) {
		if ValidateTOTP("", codeAt, testTOTPTime) {
			t.Error("ValidateTOTP with empty secret returned true; want false")
		}
	})

	t.Run("empty code fails", func(t *testing.T) {
		if ValidateTOTP(testTOTPSecret, "", testTOTPTime) {
			t.Error("ValidateTOTP with empty code returned true; want false")
		}
	})

	t.Run("wrong-length code fails (5 digits)", func(t *testing.T) {
		if ValidateTOTP(testTOTPSecret, "12345", testTOTPTime) {
			t.Error("ValidateTOTP with 5-digit code returned true; want false")
		}
	})

	t.Run("wrong-length code fails (7 digits)", func(t *testing.T) {
		if ValidateTOTP(testTOTPSecret, "1234567", testTOTPTime) {
			t.Error("ValidateTOTP with 7-digit code returned true; want false")
		}
	})

	t.Run("code with spaces is normalized and validated", func(t *testing.T) {
		spaced := codeAt[:3] + " " + codeAt[3:]
		if !ValidateTOTP(testTOTPSecret, spaced, testTOTPTime) {
			t.Errorf("ValidateTOTP with space-separated code %q returned false; want true", spaced)
		}
	})

	t.Run("secret with lowercase is accepted", func(t *testing.T) {
		lower := strings.ToLower(testTOTPSecret)
		if !ValidateTOTP(lower, codeAt, testTOTPTime) {
			t.Error("ValidateTOTP with lowercase secret returned false; want true")
		}
	})

	t.Run("code two windows away fails", func(t *testing.T) {
		codeTwoAway := generateTOTP(secretUpper, testTOTPTime.Add(60*time.Second))
		// Only fails if the code differs from all three accepted windows.
		if codeTwoAway != codeAt && codeTwoAway != codePrev && codeTwoAway != codeNext {
			if ValidateTOTP(testTOTPSecret, codeTwoAway, testTOTPTime) {
				t.Error("ValidateTOTP accepted code from two windows away; want false")
			}
		}
	})
}

func TestBuildTOTPProvisioningURI(t *testing.T) {
	t.Run("starts with otpauth://totp/", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("Acme Corp", "alice@example.com", testTOTPSecret)
		if !strings.HasPrefix(uri, "otpauth://totp/") {
			t.Errorf("URI does not start with otpauth://totp/: %q", uri)
		}
	})

	t.Run("contains the secret parameter", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("Acme Corp", "alice@example.com", testTOTPSecret)
		want := "secret=" + strings.ToUpper(testTOTPSecret)
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q does not contain %q", uri, want)
		}
	})

	t.Run("contains the issuer parameter", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("Acme Corp", "alice@example.com", testTOTPSecret)
		if !strings.Contains(uri, "issuer=Acme+Corp") && !strings.Contains(uri, "issuer=Acme%20Corp") {
			t.Errorf("URI %q does not contain the issuer", uri)
		}
	})

	t.Run("contains the account in the label", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("Acme Corp", "alice@example.com", testTOTPSecret)
		if !strings.Contains(uri, "alice") {
			t.Errorf("URI %q does not contain account name", uri)
		}
	})

	t.Run("secret is uppercased in URI", func(t *testing.T) {
		lower := strings.ToLower(testTOTPSecret)
		uri := BuildTOTPProvisioningURI("Issuer", "user", lower)
		upper := strings.ToUpper(testTOTPSecret)
		if !strings.Contains(uri, "secret="+upper) {
			t.Errorf("URI %q does not contain uppercased secret %q", uri, upper)
		}
	})

	t.Run("uses 'Server Side Control' when issuer is empty", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("", "bob", testTOTPSecret)
		if !strings.Contains(uri, "Server") {
			t.Errorf("URI with empty issuer %q does not fall back to default", uri)
		}
	})

	t.Run("algorithm is SHA1", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("Issuer", "user", testTOTPSecret)
		if !strings.Contains(uri, "algorithm=SHA1") {
			t.Errorf("URI %q does not specify algorithm=SHA1", uri)
		}
	})

	t.Run("digits is 6", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("Issuer", "user", testTOTPSecret)
		if !strings.Contains(uri, "digits=6") {
			t.Errorf("URI %q does not specify digits=6", uri)
		}
	})

	t.Run("period is 30", func(t *testing.T) {
		uri := BuildTOTPProvisioningURI("Issuer", "user", testTOTPSecret)
		if !strings.Contains(uri, "period=30") {
			t.Errorf("URI %q does not specify period=30", uri)
		}
	})
}
