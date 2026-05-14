package system

import (
	"strings"
	"testing"
)

func TestS3RequestURL(t *testing.T) {
	t.Run("us-east-1 uses global endpoint without region", func(t *testing.T) {
		url := s3RequestURL("us-east-1", "mybucket", "mykey", "")
		if !strings.Contains(url, "mybucket.s3.amazonaws.com") {
			t.Errorf("expected virtual-hosted URL without region, got %q", url)
		}
		if strings.Contains(url, "us-east-1") {
			t.Errorf("expected no region in us-east-1 URL, got %q", url)
		}
	})

	t.Run("other region includes region in hostname", func(t *testing.T) {
		url := s3RequestURL("us-west-2", "mybucket", "mykey", "")
		if !strings.Contains(url, "mybucket.s3.us-west-2.amazonaws.com") {
			t.Errorf("expected regional hostname, got %q", url)
		}
	})

	t.Run("eu-central-1 includes region in hostname", func(t *testing.T) {
		url := s3RequestURL("eu-central-1", "mybucket", "mykey", "")
		if !strings.Contains(url, "mybucket.s3.eu-central-1.amazonaws.com") {
			t.Errorf("expected regional hostname for eu-central-1, got %q", url)
		}
	})

	t.Run("key appears as path after slash", func(t *testing.T) {
		url := s3RequestURL("us-east-1", "mybucket", "mykey", "")
		if !strings.HasSuffix(url, "/mykey") {
			t.Errorf("expected key as path, got %q", url)
		}
	})

	t.Run("key with directory structure", func(t *testing.T) {
		url := s3RequestURL("us-east-1", "mybucket", "backups/2024/archive.tar.gz", "")
		if !strings.Contains(url, "/backups/2024/archive.tar.gz") {
			t.Errorf("expected nested key in path, got %q", url)
		}
	})

	t.Run("rawQuery is appended with question mark", func(t *testing.T) {
		url := s3RequestURL("us-east-1", "mybucket", "", "list-type=2&max-keys=1000")
		if !strings.Contains(url, "?list-type=2&max-keys=1000") {
			t.Errorf("expected query string appended, got %q", url)
		}
	})

	t.Run("empty key produces trailing slash only", func(t *testing.T) {
		url := s3RequestURL("us-east-1", "mybucket", "", "")
		if !strings.HasSuffix(url, "/") {
			t.Errorf("expected URL to end with /, got %q", url)
		}
	})

	t.Run("URL uses HTTPS scheme", func(t *testing.T) {
		url := s3RequestURL("us-east-1", "mybucket", "mykey", "")
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("expected HTTPS URL, got %q", url)
		}
	})

	t.Run("bucket name is virtual-hosted as subdomain", func(t *testing.T) {
		url := s3RequestURL("us-west-1", "my-special-bucket", "key.txt", "")
		if !strings.HasPrefix(url, "https://my-special-bucket.s3.") {
			t.Errorf("expected bucket as subdomain, got %q", url)
		}
	})

	t.Run("rawQuery not appended when empty", func(t *testing.T) {
		url := s3RequestURL("us-east-1", "mybucket", "mykey", "")
		if strings.Contains(url, "?") {
			t.Errorf("expected no query string when rawQuery is empty, got %q", url)
		}
	})
}

func TestParseS3Error(t *testing.T) {
	t.Run("valid XML with Code returns formatted error", func(t *testing.T) {
		body := []byte(`<?xml version="1.0"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>`)
		err := parseS3Error(404, body)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "NoSuchBucket") {
			t.Errorf("error should contain 'NoSuchBucket', got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "s3") {
			t.Errorf("error should contain 's3', got %q", err.Error())
		}
	})

	t.Run("valid XML with Code and Message", func(t *testing.T) {
		body := []byte(`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
		err := parseS3Error(403, body)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "AccessDenied") {
			t.Errorf("expected 'AccessDenied' in error, got %q", err.Error())
		}
	})

	t.Run("invalid XML falls back to status code", func(t *testing.T) {
		err := parseS3Error(500, []byte("not xml"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("expected status code in error, got %q", err.Error())
		}
	})

	t.Run("empty body falls back to status code only", func(t *testing.T) {
		err := parseS3Error(503, []byte(""))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "503") {
			t.Errorf("expected status code in error, got %q", err.Error())
		}
	})

	t.Run("non-XML body includes body text", func(t *testing.T) {
		err := parseS3Error(400, []byte("Bad Request"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "400") {
			t.Errorf("expected 400 in error, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "Bad Request") {
			t.Errorf("expected body text in error, got %q", err.Error())
		}
	})

	t.Run("XML with no Code falls through to body", func(t *testing.T) {
		body := []byte(`<SomeOtherElement><Foo>bar</Foo></SomeOtherElement>`)
		err := parseS3Error(400, body)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		// Should contain status code
		if !strings.Contains(err.Error(), "400") {
			t.Errorf("expected 400 in error for unknown XML, got %q", err.Error())
		}
	})
}

func TestS3ClientConfigured(t *testing.T) {
	t.Run("nil client is not configured", func(t *testing.T) {
		var c *S3Client
		if c.Configured() {
			t.Error("expected Configured()=false for nil client")
		}
	})

	t.Run("empty access key is not configured", func(t *testing.T) {
		c := NewS3Client("", "secretkey", "us-east-1")
		if c.Configured() {
			t.Error("expected Configured()=false when access key is empty")
		}
	})

	t.Run("empty secret key is not configured", func(t *testing.T) {
		c := NewS3Client("accesskey", "", "us-east-1")
		if c.Configured() {
			t.Error("expected Configured()=false when secret key is empty")
		}
	})

	t.Run("both keys empty is not configured", func(t *testing.T) {
		c := NewS3Client("", "", "us-east-1")
		if c.Configured() {
			t.Error("expected Configured()=false when both keys are empty")
		}
	})

	t.Run("both keys set is configured", func(t *testing.T) {
		c := NewS3Client("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1")
		if !c.Configured() {
			t.Error("expected Configured()=true when both keys are set")
		}
	})

	t.Run("whitespace-only keys are not configured", func(t *testing.T) {
		c := NewS3Client("   ", "   ", "us-east-1")
		if c.Configured() {
			t.Error("expected Configured()=false for whitespace-only keys")
		}
	})

	t.Run("default region applied when empty", func(t *testing.T) {
		c := NewS3Client("key", "secret", "")
		// region defaults to us-east-1; can verify via URL generation
		url := s3RequestURL(c.region, "bucket", "key", "")
		if !strings.Contains(url, "bucket.s3.amazonaws.com") {
			t.Errorf("expected us-east-1 default endpoint, got %q", url)
		}
	})

	t.Run("region is trimmed of whitespace", func(t *testing.T) {
		c := NewS3Client("key", "secret", "  us-west-2  ")
		if c.region != "us-west-2" {
			t.Errorf("expected region to be trimmed, got %q", c.region)
		}
	})
}
