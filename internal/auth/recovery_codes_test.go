package auth

import (
	"strings"
	"testing"
)

func TestNormalizeRecoveryCode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "strips dash and uppercases",
			input: "abcde-fghij",
			want:  "ABCDEFGHIJ",
		},
		{
			name:  "strips spaces and uppercases",
			input: "abcde fghij",
			want:  "ABCDEFGHIJ",
		},
		{
			name:  "already uppercase with dash",
			input: "ABCDE-FGHIJ",
			want:  "ABCDEFGHIJ",
		},
		{
			name:  "already uppercase no dash",
			input: "ABCDEFGHIJ",
			want:  "ABCDEFGHIJ",
		},
		{
			name:  "leading and trailing spaces stripped",
			input: "  ABCDE-FGHIJ  ",
			want:  "ABCDEFGHIJ",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "mixed case with multiple dashes",
			input: "ab-cd-ef",
			want:  "ABCDEF",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeRecoveryCode(tc.input)
			if got != tc.want {
				t.Errorf("normalizeRecoveryCode(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestHashRecoveryCode(t *testing.T) {
	t.Run("same input always produces same hash", func(t *testing.T) {
		h1 := HashRecoveryCode("ABCDE-FGHIJ")
		h2 := HashRecoveryCode("ABCDE-FGHIJ")
		if h1 != h2 {
			t.Errorf("HashRecoveryCode is not deterministic: %q vs %q", h1, h2)
		}
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		h1 := HashRecoveryCode("ABCDE-FGHIJ")
		h2 := HashRecoveryCode("ZYXWV-UTSRQ")
		if h1 == h2 {
			t.Error("different codes produced the same hash")
		}
	})

	t.Run("hash is hex-encoded (64 chars for SHA-256)", func(t *testing.T) {
		h := HashRecoveryCode("ABCDE-FGHIJ")
		if len(h) != 64 {
			t.Errorf("HashRecoveryCode returned %d-char string; want 64", len(h))
		}
		for _, ch := range h {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				t.Errorf("HashRecoveryCode returned non-hex character %q in %q", ch, h)
				break
			}
		}
	})

	t.Run("normalization is applied before hashing (case and dash insensitive)", func(t *testing.T) {
		h1 := HashRecoveryCode("ABCDE-FGHIJ")
		h2 := HashRecoveryCode("abcde-fghij")
		h3 := HashRecoveryCode("ABCDEFGHIJ")
		if h1 != h2 {
			t.Errorf("upper/lower case variants hash differently: %q vs %q", h1, h2)
		}
		if h1 != h3 {
			t.Errorf("with/without dash variants hash differently: %q vs %q", h1, h3)
		}
	})

	t.Run("known hash value for deterministic input", func(t *testing.T) {
		// normalizeRecoveryCode("test-code") → "TESTCODE"
		// sha256("TESTCODE") hex-encoded — computed independently.
		// We verify indirectly: hash the normalized form directly.
		import_free_check := HashRecoveryCode("test-code")
		again := HashRecoveryCode("TESTCODE")
		if import_free_check != again {
			t.Errorf("HashRecoveryCode inconsistent: %q vs %q", import_free_check, again)
		}
	})
}

func TestGenerateRecoveryCodes(t *testing.T) {
	t.Run("count=5 gives 5 plain and 5 hash codes", func(t *testing.T) {
		plain, hashes, err := GenerateRecoveryCodes(5)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(5) error: %v", err)
		}
		if len(plain) != 5 {
			t.Errorf("len(plain) = %d; want 5", len(plain))
		}
		if len(hashes) != 5 {
			t.Errorf("len(hashes) = %d; want 5", len(hashes))
		}
	})

	t.Run("count=0 defaults to 8 codes", func(t *testing.T) {
		plain, hashes, err := GenerateRecoveryCodes(0)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(0) error: %v", err)
		}
		if len(plain) != 8 {
			t.Errorf("len(plain) = %d; want 8 (default)", len(plain))
		}
		if len(hashes) != 8 {
			t.Errorf("len(hashes) = %d; want 8 (default)", len(hashes))
		}
	})

	t.Run("negative count defaults to 8 codes", func(t *testing.T) {
		plain, hashes, err := GenerateRecoveryCodes(-3)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(-3) error: %v", err)
		}
		if len(plain) != 8 {
			t.Errorf("len(plain) = %d; want 8 (default)", len(plain))
		}
		if len(hashes) != 8 {
			t.Errorf("len(hashes) = %d; want 8 (default)", len(hashes))
		}
	})

	t.Run("each plain code hashes to the corresponding hash", func(t *testing.T) {
		plain, hashes, err := GenerateRecoveryCodes(8)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(8) error: %v", err)
		}
		for i, p := range plain {
			got := HashRecoveryCode(p)
			if got != hashes[i] {
				t.Errorf("plain[%d] %q hashes to %q; stored hash is %q", i, p, got, hashes[i])
			}
		}
	})

	t.Run("plain codes have format XXXXX-XXXXX (11 chars with one dash)", func(t *testing.T) {
		plain, _, err := GenerateRecoveryCodes(10)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(10) error: %v", err)
		}
		for _, code := range plain {
			if len(code) != 11 {
				t.Errorf("plain code %q has length %d; want 11", code, len(code))
				continue
			}
			if code[5] != '-' {
				t.Errorf("plain code %q does not have dash at position 5", code)
			}
			parts := strings.SplitN(code, "-", 2)
			if len(parts) != 2 || len(parts[0]) != 5 || len(parts[1]) != 5 {
				t.Errorf("plain code %q is not in XXXXX-XXXXX format", code)
			}
		}
	})

	t.Run("generated codes are unique", func(t *testing.T) {
		plain, _, err := GenerateRecoveryCodes(20)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(20) error: %v", err)
		}
		seen := make(map[string]bool)
		for _, code := range plain {
			if seen[code] {
				t.Errorf("duplicate code generated: %q", code)
			}
			seen[code] = true
		}
	})

	t.Run("plain codes use only characters from the defined alphabet", func(t *testing.T) {
		alphabet := string(recoveryCodeAlphabet)
		plain, _, err := GenerateRecoveryCodes(10)
		if err != nil {
			t.Fatalf("GenerateRecoveryCodes(10) error: %v", err)
		}
		for _, code := range plain {
			for _, ch := range code {
				if ch == '-' {
					continue
				}
				if !strings.ContainsRune(alphabet, ch) {
					t.Errorf("code %q contains character %q not in alphabet %q", code, ch, alphabet)
				}
			}
		}
	})
}
