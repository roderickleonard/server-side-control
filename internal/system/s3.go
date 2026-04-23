package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const s3Service = "s3"

var s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)
var s3KeyPattern = regexp.MustCompile(`^[A-Za-z0-9!_.*'()/\-]+$`)

// S3Client is a minimal pure-Go S3 client supporting single PUT, GET,
// DELETE, and ListObjectsV2 with SigV4 signing. It's enough for backup
// upload, history listing, and pruning use cases.
type S3Client struct {
	accessKeyID     string
	secretAccessKey string
	region          string
	httpClient      *http.Client
}

func NewS3Client(accessKeyID string, secretAccessKey string, region string) *S3Client {
	region = strings.TrimSpace(region)
	if region == "" {
		region = "us-east-1"
	}
	return &S3Client{
		accessKeyID:     strings.TrimSpace(accessKeyID),
		secretAccessKey: strings.TrimSpace(secretAccessKey),
		region:          region,
		httpClient:      &http.Client{Timeout: 0},
	}
}

func (c *S3Client) Configured() bool {
	if c == nil {
		return false
	}
	return c.accessKeyID != "" && c.secretAccessKey != ""
}

// PutObjectFile streams the local file at filePath to s3://bucket/key.
// The Content-Type header is honoured if provided. The file's body
// hash is precomputed (SigV4 requires the body hash up-front).
func (c *S3Client) PutObjectFile(ctx context.Context, bucket string, key string, filePath string, contentType string) error {
	if !c.Configured() {
		return ErrAWSCredentialsMissing
	}
	bucket = strings.TrimSpace(bucket)
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if !s3BucketPattern.MatchString(bucket) {
		return ErrInvalidS3Bucket
	}
	if !s3KeyPattern.MatchString(key) || strings.Contains(key, "..") {
		return ErrInvalidS3Key
	}
	stat, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat backup file: %w", err)
	}
	bodyHash, err := sha256SumFile(filePath)
	if err != nil {
		return fmt.Errorf("hash backup file: %w", err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open backup file: %w", err)
	}
	defer file.Close()

	requestURL := s3RequestURL(c.region, bucket, key, "")
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, requestURL, file)
	if err != nil {
		return err
	}
	req.ContentLength = stat.Size()
	if strings.TrimSpace(contentType) != "" {
		req.Header.Set("Content-Type", contentType)
	}

	SignAWSV4(req, AWSV4SignSpec{
		AccessKeyID:     c.accessKeyID,
		SecretAccessKey: c.secretAccessKey,
		Region:          c.region,
		Service:         s3Service,
		BodyHashHex:     bodyHash,
	})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return parseS3Error(resp.StatusCode, body)
	}
	return nil
}

// DeleteObject removes an S3 object.
func (c *S3Client) DeleteObject(ctx context.Context, bucket string, key string) error {
	if !c.Configured() {
		return ErrAWSCredentialsMissing
	}
	bucket = strings.TrimSpace(bucket)
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if !s3BucketPattern.MatchString(bucket) {
		return ErrInvalidS3Bucket
	}
	if !s3KeyPattern.MatchString(key) || strings.Contains(key, "..") {
		return ErrInvalidS3Key
	}
	requestURL := s3RequestURL(c.region, bucket, key, "")
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, requestURL, nil)
	if err != nil {
		return err
	}
	SignAWSV4(req, AWSV4SignSpec{
		AccessKeyID:     c.accessKeyID,
		SecretAccessKey: c.secretAccessKey,
		Region:          c.region,
		Service:         s3Service,
	})
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("s3 delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return parseS3Error(resp.StatusCode, body)
	}
	return nil
}

type S3ObjectListing struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// ListObjects returns up to 1000 objects under prefix sorted by key
// descending (so newest backup folder name sorts first when the key
// starts with an ISO timestamp).
func (c *S3Client) ListObjects(ctx context.Context, bucket string, prefix string) ([]S3ObjectListing, error) {
	if !c.Configured() {
		return nil, ErrAWSCredentialsMissing
	}
	bucket = strings.TrimSpace(bucket)
	if !s3BucketPattern.MatchString(bucket) {
		return nil, ErrInvalidS3Bucket
	}
	prefix = strings.TrimPrefix(strings.TrimSpace(prefix), "/")
	query := "list-type=2&max-keys=1000"
	if prefix != "" {
		query = query + "&prefix=" + encodeAWSV4Segment(prefix)
	}
	requestURL := s3RequestURL(c.region, bucket, "", query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	SignAWSV4(req, AWSV4SignSpec{
		AccessKeyID:     c.accessKeyID,
		SecretAccessKey: c.secretAccessKey,
		Region:          c.region,
		Service:         s3Service,
	})
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3 list: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, parseS3Error(resp.StatusCode, body)
	}
	var parsed struct {
		XMLName  xml.Name `xml:"ListBucketResult"`
		Contents []struct {
			Key          string `xml:"Key"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode list response: %w", err)
	}
	listings := make([]S3ObjectListing, 0, len(parsed.Contents))
	for _, item := range parsed.Contents {
		ts, _ := time.Parse(time.RFC3339, item.LastModified)
		listings = append(listings, S3ObjectListing{
			Key:          item.Key,
			Size:         item.Size,
			LastModified: ts,
		})
	}
	sort.Slice(listings, func(i, j int) bool { return listings[i].Key > listings[j].Key })
	return listings, nil
}

// s3RequestURL builds a virtual-hosted-style URL. For us-east-1 the
// host is bucket.s3.amazonaws.com; for other regions it's
// bucket.s3.<region>.amazonaws.com.
func s3RequestURL(region string, bucket string, key string, rawQuery string) string {
	host := bucket + ".s3." + region + ".amazonaws.com"
	if region == "us-east-1" {
		host = bucket + ".s3.amazonaws.com"
	}
	url := "https://" + host + "/"
	if key != "" {
		url = url + key
	}
	if rawQuery != "" {
		url = url + "?" + rawQuery
	}
	return url
}

func sha256SumFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type s3ErrorResponse struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func parseS3Error(status int, body []byte) error {
	var parsed s3ErrorResponse
	if err := xml.Unmarshal(body, &parsed); err == nil && parsed.Code != "" {
		return fmt.Errorf("s3 %s: %s", parsed.Code, parsed.Message)
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return fmt.Errorf("s3 request failed with HTTP %d", status)
	}
	return fmt.Errorf("s3 request failed with HTTP %d: %s", status, trimmed)
}

// ErrInvalidS3Bucket / ErrInvalidS3Key are exported so handlers can
// translate them to friendly messages.
var (
	ErrInvalidS3Bucket = errors.New("invalid s3 bucket name")
	ErrInvalidS3Key    = errors.New("invalid s3 object key")
)
