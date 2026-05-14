package system

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCanonicalAWSPath(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"root path", "/", "/"},
		{"simple path", "/foo/bar", "/foo/bar"},
		{"path with space", "/foo bar/baz", "/foo%20bar/baz"},
		{"empty path becomes root", "", "/"},
		{"path with special chars", "/my-bucket/my_key.txt", "/my-bucket/my_key.txt"},
		{"path with tilde", "/foo/bar~baz", "/foo/bar~baz"},
		{"path with slash only segments", "/a/b/c", "/a/b/c"},
		{"path with at sign", "/foo/@bar", "/foo/%40bar"},
		{"path with hash", "/foo/#bar", "/foo/%23bar"},
		{"path with percent", "/foo/%bar", "/foo/%25bar"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalAWSPath(tc.input)
			if got != tc.want {
				t.Errorf("canonicalAWSPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestEncodeAWSV4Segment(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain letters", "hello", "hello"},
		{"with space", "hello world", "hello%20world"},
		{"slash", "/", "%2F"},
		{"unreserved chars stay as-is", "abc-_.", "abc-_."},
		{"tilde is unreserved", "foo~bar", "foo~bar"},
		{"digits", "abc123", "abc123"},
		{"ampersand", "foo&bar", "foo%26bar"},
		{"equals", "foo=bar", "foo%3Dbar"},
		{"plus", "foo+bar", "foo%2Bbar"},
		{"empty string", "", ""},
		{"uppercase letters", "HELLO", "HELLO"},
		{"mixed case and special", "Hello World!", "Hello%20World%21"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := encodeAWSV4Segment(tc.input)
			if got != tc.want {
				t.Errorf("encodeAWSV4Segment(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCanonicalAWSQueryString(t *testing.T) {
	t.Run("empty query", func(t *testing.T) {
		got := CanonicalAWSQueryString(url.Values{})
		if got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("single parameter", func(t *testing.T) {
		q := url.Values{}
		q.Set("key", "value")
		got := CanonicalAWSQueryString(q)
		if got != "key=value" {
			t.Errorf("expected %q, got %q", "key=value", got)
		}
	})

	t.Run("multiple params sorted alphabetically", func(t *testing.T) {
		q := url.Values{}
		q.Set("zebra", "last")
		q.Set("apple", "first")
		q.Set("mango", "middle")
		got := CanonicalAWSQueryString(q)
		want := "apple=first&mango=middle&zebra=last"
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})

	t.Run("special chars in values are percent-encoded", func(t *testing.T) {
		q := url.Values{}
		q.Set("prefix", "my folder/")
		got := CanonicalAWSQueryString(q)
		if !strings.Contains(got, "%2F") {
			t.Errorf("expected slash to be encoded as %%2F in %q", got)
		}
		if !strings.Contains(got, "%20") {
			t.Errorf("expected space to be encoded as %%20 in %q", got)
		}
	})

	t.Run("multiple values for same key are sorted", func(t *testing.T) {
		q := url.Values{}
		q["versions"] = []string{"v2", "v1", "v3"}
		got := CanonicalAWSQueryString(q)
		want := "versions=v1&versions=v2&versions=v3"
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})

	t.Run("key with special chars is encoded", func(t *testing.T) {
		q := url.Values{}
		q.Set("list-type", "2")
		got := CanonicalAWSQueryString(q)
		// dash is unreserved in AWS SigV4 segment encoding
		if got != "list-type=2" {
			t.Errorf("expected %q, got %q", "list-type=2", got)
		}
	})
}

func TestHmacSHA256(t *testing.T) {
	t.Run("output length is 32 bytes", func(t *testing.T) {
		result := hmacSHA256([]byte("secret"), "data")
		if len(result) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(result))
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		a := hmacSHA256([]byte("key"), "message")
		b := hmacSHA256([]byte("key"), "message")
		if !bytes.Equal(a, b) {
			t.Error("expected identical outputs for identical inputs")
		}
	})

	t.Run("different keys produce different output", func(t *testing.T) {
		a := hmacSHA256([]byte("key1"), "message")
		b := hmacSHA256([]byte("key2"), "message")
		if bytes.Equal(a, b) {
			t.Error("expected different outputs for different keys")
		}
	})

	t.Run("different data produces different output", func(t *testing.T) {
		a := hmacSHA256([]byte("key"), "message1")
		b := hmacSHA256([]byte("key"), "message2")
		if bytes.Equal(a, b) {
			t.Error("expected different outputs for different data")
		}
	})

	t.Run("known HMAC-SHA256 test vector", func(t *testing.T) {
		// RFC 4231 test vector #1
		key := []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b}
		data := "Hi There"
		result := hmacSHA256(key, data)
		want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
		got := hex.EncodeToString(result)
		if got != want {
			t.Errorf("HMAC-SHA256 test vector: want %q, got %q", want, got)
		}
	})
}

func TestSignAWSV4(t *testing.T) {
	fixedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	t.Run("sets X-Amz-Date header", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://s3.amazonaws.com/mybucket/mykey", nil)
		if err != nil {
			t.Fatal(err)
		}
		SignAWSV4(req, AWSV4SignSpec{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
		})
		amzDate := req.Header.Get("X-Amz-Date")
		if amzDate == "" {
			t.Error("X-Amz-Date header not set")
		}
		// Fixed time 2024-01-15T10:30:00Z → 20240115T103000Z
		want := "20240115T103000Z"
		if amzDate != want {
			t.Errorf("X-Amz-Date: want %q, got %q", want, amzDate)
		}
	})

	t.Run("sets Authorization header with correct algorithm prefix", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://s3.amazonaws.com/mybucket/mykey", nil)
		if err != nil {
			t.Fatal(err)
		}
		SignAWSV4(req, AWSV4SignSpec{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
		})
		auth := req.Header.Get("Authorization")
		if auth == "" {
			t.Error("Authorization header not set")
		}
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
			t.Errorf("Authorization header should start with AWS4-HMAC-SHA256, got %q", auth)
		}
	})

	t.Run("Authorization header contains Credential, SignedHeaders, Signature", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://s3.amazonaws.com/mybucket/mykey", nil)
		if err != nil {
			t.Fatal(err)
		}
		SignAWSV4(req, AWSV4SignSpec{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
		})
		auth := req.Header.Get("Authorization")
		if !strings.Contains(auth, "Credential=") {
			t.Error("Authorization missing Credential=")
		}
		if !strings.Contains(auth, "SignedHeaders=") {
			t.Error("Authorization missing SignedHeaders=")
		}
		if !strings.Contains(auth, "Signature=") {
			t.Error("Authorization missing Signature=")
		}
	})

	t.Run("sets X-Amz-Content-Sha256 header", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://s3.amazonaws.com/mybucket/mykey", nil)
		if err != nil {
			t.Fatal(err)
		}
		SignAWSV4(req, AWSV4SignSpec{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
		})
		sha := req.Header.Get("X-Amz-Content-Sha256")
		if sha == "" {
			t.Error("X-Amz-Content-Sha256 header not set")
		}
		// For an empty body, the SHA256 is a known constant
		wantEmpty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if sha != wantEmpty {
			t.Errorf("X-Amz-Content-Sha256 for empty body: want %q, got %q", wantEmpty, sha)
		}
	})

	t.Run("custom body hash is used", func(t *testing.T) {
		req, err := http.NewRequest("PUT", "https://s3.amazonaws.com/mybucket/mykey", nil)
		if err != nil {
			t.Fatal(err)
		}
		customHash := "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
		SignAWSV4(req, AWSV4SignSpec{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
			BodyHashHex:     customHash,
		})
		sha := req.Header.Get("X-Amz-Content-Sha256")
		if sha != customHash {
			t.Errorf("X-Amz-Content-Sha256: want %q, got %q", customHash, sha)
		}
	})

	t.Run("extra headers are signed and set", func(t *testing.T) {
		req, err := http.NewRequest("PUT", "https://s3.amazonaws.com/mybucket/mykey", nil)
		if err != nil {
			t.Fatal(err)
		}
		SignAWSV4(req, AWSV4SignSpec{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
			ExtraHeaders:    map[string]string{"x-amz-acl": "public-read"},
		})
		if req.Header.Get("x-amz-acl") == "" {
			t.Error("x-amz-acl extra header was not set on request")
		}
		auth := req.Header.Get("Authorization")
		if !strings.Contains(auth, "x-amz-acl") {
			t.Error("x-amz-acl should appear in SignedHeaders")
		}
	})

	t.Run("Authorization includes access key ID in credential", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://s3.amazonaws.com/mybucket/mykey", nil)
		if err != nil {
			t.Fatal(err)
		}
		accessKey := "AKIAIOSFODNN7EXAMPLE"
		SignAWSV4(req, AWSV4SignSpec{
			AccessKeyID:     accessKey,
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
		})
		auth := req.Header.Get("Authorization")
		if !strings.Contains(auth, accessKey) {
			t.Errorf("Authorization header should contain access key ID %q", accessKey)
		}
	})

	t.Run("deterministic output for same inputs", func(t *testing.T) {
		makeReq := func() *http.Request {
			req, _ := http.NewRequest("GET", "https://s3.amazonaws.com/mybucket/mykey", nil)
			return req
		}
		spec := AWSV4SignSpec{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
			Now:             fixedTime,
		}
		req1 := makeReq()
		req2 := makeReq()
		SignAWSV4(req1, spec)
		SignAWSV4(req2, spec)
		if req1.Header.Get("Authorization") != req2.Header.Get("Authorization") {
			t.Error("expected deterministic Authorization for same inputs")
		}
	})
}
