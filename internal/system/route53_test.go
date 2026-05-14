package system

import (
	"strings"
	"testing"
)

func TestXMLEscape(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text unchanged", "hello world", "hello world"},
		{"ampersand", "foo&bar", "foo&amp;bar"},
		{"less-than", "a<b", "a&lt;b"},
		{"greater-than", "a>b", "a&gt;b"},
		{"double quote", `say "hi"`, "say &#34;hi&#34;"},
		{"mixed special chars", "a&b<c>d", "a&amp;b&lt;c&gt;d"},
		{"empty string", "", ""},
		{"no special chars", "example.com", "example.com"},
		{"multiple ampersands", "a&b&c", "a&amp;b&amp;c"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := xmlEscape(tc.input)
			if got != tc.want {
				t.Errorf("xmlEscape(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestTrimHostedZoneID(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"with /hostedzone/ prefix", "/hostedzone/Z123ABC", "Z123ABC"},
		{"already trimmed", "Z123ABC", "Z123ABC"},
		{"with leading whitespace", "  /hostedzone/Z456DEF  ", "Z456DEF"},
		{"with trailing whitespace", "/hostedzone/ZXYZ789  ", "ZXYZ789"},
		{"empty string", "", ""},
		{"only prefix", "/hostedzone/", ""},
		{"complex zone ID", "/hostedzone/Z2FDTNDATAQYW2", "Z2FDTNDATAQYW2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := trimHostedZoneID(tc.input)
			if got != tc.want {
				t.Errorf("trimHostedZoneID(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeDNSRecord(t *testing.T) {
	t.Run("valid A record gets trailing dot added", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "example.com",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4"},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name != "example.com." {
			t.Errorf("expected Name %q, got %q", "example.com.", got.Name)
		}
	})

	t.Run("name already with trailing dot is preserved", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "example.com.",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4"},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name != "example.com." {
			t.Errorf("expected Name %q, got %q", "example.com.", got.Name)
		}
	})

	t.Run("type is uppercased", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "example.com",
			Type:   "a",
			TTL:    300,
			Values: []string{"1.2.3.4"},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Type != "A" {
			t.Errorf("expected Type %q, got %q", "A", got.Type)
		}
	})

	t.Run("valid CNAME record", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "www.example.com",
			Type:   "CNAME",
			TTL:    60,
			Values: []string{"example.com."},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Type != "CNAME" {
			t.Errorf("expected Type CNAME, got %q", got.Type)
		}
	})

	t.Run("TXT record value gets quoted if not already", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "example.com",
			Type:   "TXT",
			TTL:    300,
			Values: []string{"v=spf1 include:example.com ~all"},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(got.Values[0], "\"") {
			t.Errorf("TXT value should be quoted, got %q", got.Values[0])
		}
	})

	t.Run("TXT record already quoted is not double-quoted", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "example.com",
			Type:   "TXT",
			TTL:    300,
			Values: []string{`"v=spf1 ~all"`},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.HasPrefix(got.Values[0], "\"\"") {
			t.Errorf("TXT value was double-quoted: %q", got.Values[0])
		}
	})

	t.Run("empty name returns ErrInvalidDNSRecordName", func(t *testing.T) {
		raw := DNSRecord{Name: "", Type: "A", TTL: 300, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordName {
			t.Errorf("expected ErrInvalidDNSRecordName, got %v", err)
		}
	})

	t.Run("name with invalid pattern returns ErrInvalidDNSRecordName", func(t *testing.T) {
		raw := DNSRecord{Name: "---invalid", Type: "A", TTL: 300, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordName {
			t.Errorf("expected ErrInvalidDNSRecordName, got %v", err)
		}
	})

	t.Run("name with spaces is invalid", func(t *testing.T) {
		raw := DNSRecord{Name: "my domain.com", Type: "A", TTL: 300, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordName {
			t.Errorf("expected ErrInvalidDNSRecordName, got %v", err)
		}
	})

	t.Run("TTL too low returns ErrInvalidDNSRecordTTL", func(t *testing.T) {
		raw := DNSRecord{Name: "example.com", Type: "A", TTL: 10, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordTTL {
			t.Errorf("expected ErrInvalidDNSRecordTTL, got %v", err)
		}
	})

	t.Run("TTL too high returns ErrInvalidDNSRecordTTL", func(t *testing.T) {
		raw := DNSRecord{Name: "example.com", Type: "A", TTL: 604801, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordTTL {
			t.Errorf("expected ErrInvalidDNSRecordTTL, got %v", err)
		}
	})

	t.Run("TTL exactly 30 is valid", func(t *testing.T) {
		raw := DNSRecord{Name: "example.com", Type: "A", TTL: 30, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Errorf("expected no error for TTL=30, got %v", err)
		}
	})

	t.Run("TTL exactly 604800 is valid", func(t *testing.T) {
		raw := DNSRecord{Name: "example.com", Type: "A", TTL: 604800, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Errorf("expected no error for TTL=604800, got %v", err)
		}
	})

	t.Run("invalid record type returns ErrInvalidDNSRecordType", func(t *testing.T) {
		raw := DNSRecord{Name: "example.com", Type: "INVALID", TTL: 300, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordType {
			t.Errorf("expected ErrInvalidDNSRecordType, got %v", err)
		}
	})

	t.Run("empty values returns ErrInvalidDNSRecordValue", func(t *testing.T) {
		raw := DNSRecord{Name: "example.com", Type: "A", TTL: 300, Values: []string{}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordValue {
			t.Errorf("expected ErrInvalidDNSRecordValue, got %v", err)
		}
	})

	t.Run("value with newline returns ErrInvalidDNSRecordValue", func(t *testing.T) {
		raw := DNSRecord{Name: "example.com", Type: "A", TTL: 300, Values: []string{"1.2.3.4\n5.6.7.8"}}
		_, err := normalizeDNSRecord(raw)
		if err != ErrInvalidDNSRecordValue {
			t.Errorf("expected ErrInvalidDNSRecordValue, got %v", err)
		}
	})

	t.Run("wildcard name is valid", func(t *testing.T) {
		raw := DNSRecord{Name: "*.example.com", Type: "A", TTL: 300, Values: []string{"1.2.3.4"}}
		_, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Errorf("expected no error for wildcard name, got %v", err)
		}
	})

	t.Run("multiple values are all preserved", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "example.com",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4", "5.6.7.8"},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Values) != 2 {
			t.Errorf("expected 2 values, got %d", len(got.Values))
		}
	})

	t.Run("blank value strings are filtered out", func(t *testing.T) {
		raw := DNSRecord{
			Name:   "example.com",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4", "  ", "5.6.7.8"},
		}
		got, err := normalizeDNSRecord(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Values) != 2 {
			t.Errorf("expected blank values filtered, got %d values: %v", len(got.Values), got.Values)
		}
	})
}

func TestParseRoute53Error(t *testing.T) {
	t.Run("valid XML with error code", func(t *testing.T) {
		body := []byte(`<?xml version="1.0"?>
<ErrorResponse>
  <Error>
    <Code>NoSuchHostedZone</Code>
    <Message>No hosted zone found with ID: Z123</Message>
  </Error>
  <RequestId>abc-123</RequestId>
</ErrorResponse>`)
		err := parseRoute53Error(404, body)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "NoSuchHostedZone") {
			t.Errorf("error should contain code, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "route53") {
			t.Errorf("error should contain 'route53', got %q", err.Error())
		}
	})

	t.Run("InvalidChangeBatch XML response", func(t *testing.T) {
		body := []byte(`<?xml version="1.0"?>
<InvalidChangeBatch>
  <Messages>
    <Message>Tried to create resource record set [name='test.example.com.', type='A'] but it already exists</Message>
  </Messages>
</InvalidChangeBatch>`)
		err := parseRoute53Error(400, body)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "InvalidChangeBatch") {
			t.Errorf("error should contain InvalidChangeBatch, got %q", err.Error())
		}
	})

	t.Run("invalid or empty XML falls back to HTTP status", func(t *testing.T) {
		err := parseRoute53Error(500, []byte(""))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("error should contain status code 500, got %q", err.Error())
		}
	})

	t.Run("non-XML body includes body text in error", func(t *testing.T) {
		err := parseRoute53Error(403, []byte("Access Denied"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "403") {
			t.Errorf("error should contain status 403, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "Access Denied") {
			t.Errorf("error should contain body text, got %q", err.Error())
		}
	})

	t.Run("XML with no code falls through to body text", func(t *testing.T) {
		body := []byte(`<Foo><Bar>baz</Bar></Foo>`)
		err := parseRoute53Error(400, body)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		// Should contain status code since code extraction will fail
		if !strings.Contains(err.Error(), "400") {
			t.Errorf("error should contain status code, got %q", err.Error())
		}
	})
}

func TestBuildChangeXML(t *testing.T) {
	t.Run("contains the action", func(t *testing.T) {
		record := DNSRecord{
			Name:   "example.com.",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4"},
		}
		xml := buildChangeXML("CREATE", record)
		if !strings.Contains(xml, "<Action>CREATE</Action>") {
			t.Errorf("expected action CREATE in XML, got:\n%s", xml)
		}
	})

	t.Run("contains the record name", func(t *testing.T) {
		record := DNSRecord{
			Name:   "example.com.",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4"},
		}
		xml := buildChangeXML("UPSERT", record)
		if !strings.Contains(xml, "example.com.") {
			t.Errorf("expected record name in XML, got:\n%s", xml)
		}
	})

	t.Run("contains the record type", func(t *testing.T) {
		record := DNSRecord{
			Name:   "example.com.",
			Type:   "MX",
			TTL:    300,
			Values: []string{"10 mail.example.com."},
		}
		xml := buildChangeXML("UPSERT", record)
		if !strings.Contains(xml, "<Type>MX</Type>") {
			t.Errorf("expected record type MX in XML, got:\n%s", xml)
		}
	})

	t.Run("contains TTL", func(t *testing.T) {
		record := DNSRecord{
			Name:   "example.com.",
			Type:   "A",
			TTL:    3600,
			Values: []string{"1.2.3.4"},
		}
		xml := buildChangeXML("CREATE", record)
		if !strings.Contains(xml, "<TTL>3600</TTL>") {
			t.Errorf("expected TTL 3600 in XML, got:\n%s", xml)
		}
	})

	t.Run("contains record values", func(t *testing.T) {
		record := DNSRecord{
			Name:   "example.com.",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4", "5.6.7.8"},
		}
		xml := buildChangeXML("CREATE", record)
		if !strings.Contains(xml, "1.2.3.4") {
			t.Errorf("expected first value in XML, got:\n%s", xml)
		}
		if !strings.Contains(xml, "5.6.7.8") {
			t.Errorf("expected second value in XML, got:\n%s", xml)
		}
	})

	t.Run("XML-escapes special chars in values", func(t *testing.T) {
		record := DNSRecord{
			Name:   "example.com.",
			Type:   "TXT",
			TTL:    300,
			Values: []string{`"v=spf1 include:a&b ~all"`},
		}
		xml := buildChangeXML("UPSERT", record)
		if !strings.Contains(xml, "&amp;") {
			t.Errorf("expected ampersand to be escaped in XML, got:\n%s", xml)
		}
	})

	t.Run("contains required XML structure", func(t *testing.T) {
		record := DNSRecord{
			Name:   "example.com.",
			Type:   "A",
			TTL:    300,
			Values: []string{"1.2.3.4"},
		}
		xml := buildChangeXML("DELETE", record)
		for _, tag := range []string{"<Change>", "<Action>", "<ResourceRecordSet>", "<Name>", "<Type>", "<TTL>", "<ResourceRecords>", "<ResourceRecord>", "<Value>"} {
			if !strings.Contains(xml, tag) {
				t.Errorf("expected tag %q in XML output:\n%s", tag, xml)
			}
		}
	})
}

func TestRoute53DNSManagerConfigured(t *testing.T) {
	t.Run("configured when both keys are set", func(t *testing.T) {
		m := NewRoute53DNSManager("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		if !m.Configured() {
			t.Error("expected Configured()=true when both keys set")
		}
	})

	t.Run("not configured when access key empty", func(t *testing.T) {
		m := NewRoute53DNSManager("", "secretkey")
		if m.Configured() {
			t.Error("expected Configured()=false when access key empty")
		}
	})

	t.Run("not configured when secret key empty", func(t *testing.T) {
		m := NewRoute53DNSManager("accesskey", "")
		if m.Configured() {
			t.Error("expected Configured()=false when secret key empty")
		}
	})

	t.Run("not configured when both keys empty", func(t *testing.T) {
		m := NewRoute53DNSManager("", "")
		if m.Configured() {
			t.Error("expected Configured()=false when both keys empty")
		}
	})

	t.Run("nil manager is not configured", func(t *testing.T) {
		var m *route53DNSManager
		if m.Configured() {
			t.Error("expected Configured()=false for nil manager")
		}
	})

	t.Run("whitespace-only keys are not configured", func(t *testing.T) {
		m := NewRoute53DNSManager("   ", "   ")
		if m.Configured() {
			t.Error("expected Configured()=false for whitespace-only keys")
		}
	})
}
