package system

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWSV4SignSpec holds inputs for signing a single AWS SigV4 request.
type AWSV4SignSpec struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	Service         string
	Now             time.Time
	BodyHashHex     string
	ExtraHeaders    map[string]string
}

// SignAWSV4 stamps the request with SigV4 headers (Host, X-Amz-Date,
// X-Amz-Content-Sha256, Authorization). It also adds any extra headers
// from spec.ExtraHeaders into the canonical headers and signed headers
// list, allowing callers to sign things like x-amz-acl.
func SignAWSV4(req *http.Request, spec AWSV4SignSpec) {
	const algorithm = "AWS4-HMAC-SHA256"
	now := spec.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	req.Host = host

	bodyHash := strings.TrimSpace(spec.BodyHashHex)
	if bodyHash == "" {
		empty := sha256.Sum256(nil)
		bodyHash = hex.EncodeToString(empty[:])
	}

	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", bodyHash)

	headerMap := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": bodyHash,
		"x-amz-date":           amzDate,
	}
	for key, value := range spec.ExtraHeaders {
		lower := strings.ToLower(strings.TrimSpace(key))
		if lower == "" {
			continue
		}
		headerMap[lower] = strings.TrimSpace(value)
		req.Header.Set(key, value)
	}

	keys := make([]string, 0, len(headerMap))
	for key := range headerMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	headerLines := make([]string, 0, len(keys))
	for _, key := range keys {
		headerLines = append(headerLines, key+":"+headerMap[key])
	}
	canonicalHeaders := strings.Join(headerLines, "\n") + "\n"
	signedHeadersJoined := strings.Join(keys, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalAWSPath(req.URL.Path),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeadersJoined,
		bodyHash,
	}, "\n")

	hashedCanonicalBytes := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonical := hex.EncodeToString(hashedCanonicalBytes[:])

	credentialScope := strings.Join([]string{dateStamp, spec.Region, spec.Service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{algorithm, amzDate, credentialScope, hashedCanonical}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+spec.SecretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, spec.Region)
	kService := hmacSHA256(kRegion, spec.Service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		spec.AccessKeyID,
		credentialScope,
		signedHeadersJoined,
		signature,
	)
	req.Header.Set("Authorization", authorization)
}

// canonicalAWSPath URI-encodes path segments per SigV4 rules. For S3
// the path component already includes the bucket-as-prefix or the key.
func canonicalAWSPath(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		segments[index] = encodeAWSV4Segment(segment)
	}
	return strings.Join(segments, "/")
}

func encodeAWSV4Segment(value string) string {
	var buffer bytes.Buffer
	for _, b := range []byte(value) {
		switch {
		case (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~':
			buffer.WriteByte(b)
		default:
			fmt.Fprintf(&buffer, "%%%02X", b)
		}
	}
	return buffer.String()
}

// CanonicalAWSQueryString returns the canonical query string per SigV4
// rules: keys sorted, values sorted within each key, both URI-encoded.
func CanonicalAWSQueryString(query url.Values) string {
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		values := append([]string(nil), query[key]...)
		sort.Strings(values)
		for _, value := range values {
			parts = append(parts, encodeAWSV4Segment(key)+"="+encodeAWSV4Segment(value))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
