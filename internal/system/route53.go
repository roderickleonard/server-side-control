package system

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	route53Host    = "route53.amazonaws.com"
	route53Service = "route53"
	route53Region  = "us-east-1"
)

var (
	dnsRecordNamePattern = regexp.MustCompile(`^(?:\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$`)
	allowedDNSTypes      = map[string]struct{}{
		"A":     {},
		"AAAA":  {},
		"CAA":   {},
		"CNAME": {},
		"MX":    {},
		"NS":    {},
		"PTR":   {},
		"SRV":   {},
		"TXT":   {},
	}
	allowedDNSChangeActions = map[string]struct{}{
		"CREATE": {},
		"DELETE": {},
		"UPSERT": {},
	}
)

type route53DNSManager struct {
	accessKeyID     string
	secretAccessKey string
	httpClient      *http.Client
}

func NewRoute53DNSManager(accessKeyID string, secretAccessKey string) DNSManager {
	return &route53DNSManager{
		accessKeyID:     strings.TrimSpace(accessKeyID),
		secretAccessKey: strings.TrimSpace(secretAccessKey),
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *route53DNSManager) Configured() bool {
	if m == nil {
		return false
	}
	return m.accessKeyID != "" && m.secretAccessKey != ""
}

type route53HostedZonesResponse struct {
	XMLName     xml.Name `xml:"ListHostedZonesResponse"`
	HostedZones struct {
		HostedZones []struct {
			ID     string `xml:"Id"`
			Name   string `xml:"Name"`
			Config struct {
				Comment     string `xml:"Comment"`
				PrivateZone bool   `xml:"PrivateZone"`
			} `xml:"Config"`
			ResourceRecordSetCount int64 `xml:"ResourceRecordSetCount"`
		} `xml:"HostedZone"`
	} `xml:"HostedZones"`
	IsTruncated bool   `xml:"IsTruncated"`
	NextMarker  string `xml:"NextMarker"`
}

func (m *route53DNSManager) ListHostedZones() ([]DNSHostedZone, error) {
	if !m.Configured() {
		return nil, ErrAWSCredentialsMissing
	}
	zones := make([]DNSHostedZone, 0)
	marker := ""
	for {
		query := url.Values{}
		query.Set("maxitems", "100")
		if marker != "" {
			query.Set("marker", marker)
		}
		body, err := m.do(context.Background(), http.MethodGet, "/2013-04-01/hostedzone", query, nil)
		if err != nil {
			return nil, err
		}
		var parsed route53HostedZonesResponse
		if err := xml.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode list hosted zones response: %w", err)
		}
		for _, raw := range parsed.HostedZones.HostedZones {
			zones = append(zones, DNSHostedZone{
				ID:          trimHostedZoneID(raw.ID),
				Name:        strings.TrimSuffix(raw.Name, "."),
				Comment:     raw.Config.Comment,
				RecordCount: raw.ResourceRecordSetCount,
				PrivateZone: raw.Config.PrivateZone,
			})
		}
		if !parsed.IsTruncated || strings.TrimSpace(parsed.NextMarker) == "" {
			break
		}
		marker = parsed.NextMarker
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	return zones, nil
}

type route53RecordSetsResponse struct {
	XMLName            xml.Name `xml:"ListResourceRecordSetsResponse"`
	ResourceRecordSets struct {
		Records []struct {
			Name            string `xml:"Name"`
			Type            string `xml:"Type"`
			TTL             int64  `xml:"TTL"`
			ResourceRecords struct {
				Records []struct {
					Value string `xml:"Value"`
				} `xml:"ResourceRecord"`
			} `xml:"ResourceRecords"`
		} `xml:"ResourceRecordSet"`
	} `xml:"ResourceRecordSets"`
	IsTruncated          bool   `xml:"IsTruncated"`
	NextRecordName       string `xml:"NextRecordName"`
	NextRecordType       string `xml:"NextRecordType"`
	NextRecordIdentifier string `xml:"NextRecordIdentifier"`
}

func (m *route53DNSManager) ListRecords(zoneID string) ([]DNSRecord, error) {
	if !m.Configured() {
		return nil, ErrAWSCredentialsMissing
	}
	zoneID = trimHostedZoneID(zoneID)
	if zoneID == "" {
		return nil, ErrInvalidDNSZone
	}
	records := make([]DNSRecord, 0)
	startName := ""
	startType := ""
	for {
		query := url.Values{}
		query.Set("maxitems", "100")
		if startName != "" {
			query.Set("name", startName)
		}
		if startType != "" {
			query.Set("type", startType)
		}
		body, err := m.do(context.Background(), http.MethodGet, "/2013-04-01/hostedzone/"+zoneID+"/rrset", query, nil)
		if err != nil {
			return nil, err
		}
		var parsed route53RecordSetsResponse
		if err := xml.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode list records response: %w", err)
		}
		for _, raw := range parsed.ResourceRecordSets.Records {
			values := make([]string, 0, len(raw.ResourceRecords.Records))
			for _, v := range raw.ResourceRecords.Records {
				values = append(values, v.Value)
			}
			records = append(records, DNSRecord{
				Name:   strings.TrimSuffix(raw.Name, "."),
				Type:   raw.Type,
				TTL:    raw.TTL,
				Values: values,
			})
		}
		if !parsed.IsTruncated || strings.TrimSpace(parsed.NextRecordName) == "" {
			break
		}
		startName = parsed.NextRecordName
		startType = parsed.NextRecordType
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Type < records[j].Type
	})
	return records, nil
}

func (m *route53DNSManager) ApplyChange(spec DNSChangeSpec) error {
	if !m.Configured() {
		return ErrAWSCredentialsMissing
	}
	zoneID := trimHostedZoneID(spec.ZoneID)
	if zoneID == "" {
		return ErrInvalidDNSZone
	}
	action := strings.ToUpper(strings.TrimSpace(spec.Action))
	if _, ok := allowedDNSChangeActions[action]; !ok {
		return fmt.Errorf("unsupported dns change action: %s", spec.Action)
	}
	record, err := normalizeDNSRecord(spec.Record)
	if err != nil {
		return err
	}
	changes := make([]string, 0, 2)
	if action == "DELETE" || (action == "UPSERT" && (strings.TrimSpace(spec.OldName) != "" || strings.TrimSpace(spec.OldType) != "")) {
		oldName := record.Name
		oldType := record.Type
		if strings.TrimSpace(spec.OldName) != "" {
			oldName = strings.TrimSpace(spec.OldName)
		}
		if strings.TrimSpace(spec.OldType) != "" {
			oldType = strings.ToUpper(strings.TrimSpace(spec.OldType))
		}
		records, listErr := m.ListRecords(zoneID)
		if listErr != nil {
			return fmt.Errorf("locate existing record: %w", listErr)
		}
		var existing *DNSRecord
		for index := range records {
			if strings.EqualFold(records[index].Name, oldName) && strings.EqualFold(records[index].Type, oldType) {
				existing = &records[index]
				break
			}
		}
		if existing == nil {
			if action == "DELETE" {
				return fmt.Errorf("record %s %s not found in zone", oldName, oldType)
			}
			// fall through: nothing to delete, just create
		} else {
			changes = append(changes, buildChangeXML("DELETE", *existing))
		}
		if action == "DELETE" {
			// nothing else
		} else {
			changes = append(changes, buildChangeXML("CREATE", record))
		}
	} else {
		changes = append(changes, buildChangeXML(action, record))
	}

	payload := `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>` + strings.Join(changes, "") + `</Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>`

	_, err = m.do(context.Background(), http.MethodPost, "/2013-04-01/hostedzone/"+zoneID+"/rrset", nil, []byte(payload))
	return err
}

func buildChangeXML(action string, record DNSRecord) string {
	resourceRecords := strings.Builder{}
	for _, value := range record.Values {
		resourceRecords.WriteString("<ResourceRecord><Value>")
		resourceRecords.WriteString(xmlEscape(value))
		resourceRecords.WriteString("</Value></ResourceRecord>")
	}
	return `<Change>
      <Action>` + action + `</Action>
      <ResourceRecordSet>
        <Name>` + xmlEscape(record.Name) + `</Name>
        <Type>` + record.Type + `</Type>
        <TTL>` + strconv.FormatInt(record.TTL, 10) + `</TTL>
        <ResourceRecords>` + resourceRecords.String() + `</ResourceRecords>
      </ResourceRecordSet>
    </Change>`
}

func xmlEscape(value string) string {
	var buffer bytes.Buffer
	_ = xml.EscapeText(&buffer, []byte(value))
	return buffer.String()
}

func trimHostedZoneID(raw string) string {
	id := strings.TrimSpace(raw)
	id = strings.TrimPrefix(id, "/hostedzone/")
	return id
}

func normalizeDNSRecord(raw DNSRecord) (DNSRecord, error) {
	name := strings.TrimSpace(raw.Name)
	if name == "" || !dnsRecordNamePattern.MatchString(name) || len(name) > 253 {
		return DNSRecord{}, ErrInvalidDNSRecordName
	}
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	recordType := strings.ToUpper(strings.TrimSpace(raw.Type))
	if _, ok := allowedDNSTypes[recordType]; !ok {
		return DNSRecord{}, ErrInvalidDNSRecordType
	}
	if raw.TTL < 30 || raw.TTL > 604800 {
		return DNSRecord{}, ErrInvalidDNSRecordTTL
	}
	values := make([]string, 0, len(raw.Values))
	for _, value := range raw.Values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if strings.ContainsAny(trimmed, "\r\n") {
			return DNSRecord{}, ErrInvalidDNSRecordValue
		}
		if recordType == "TXT" && !strings.HasPrefix(trimmed, "\"") {
			trimmed = "\"" + strings.ReplaceAll(trimmed, "\"", "\\\"") + "\""
		}
		values = append(values, trimmed)
	}
	if len(values) == 0 {
		return DNSRecord{}, ErrInvalidDNSRecordValue
	}
	return DNSRecord{Name: name, Type: recordType, TTL: raw.TTL, Values: values}, nil
}

func (m *route53DNSManager) do(ctx context.Context, method string, path string, query url.Values, body []byte) ([]byte, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
	}
	requestURL := "https://" + route53Host + path
	if len(query) > 0 {
		requestURL = requestURL + "?" + CanonicalAWSQueryString(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = route53Host
	if method == http.MethodPost || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/xml")
	}
	bodyHashBytes := sha256.Sum256(body)
	SignAWSV4(req, AWSV4SignSpec{
		AccessKeyID:     m.accessKeyID,
		SecretAccessKey: m.secretAccessKey,
		Region:          route53Region,
		Service:         route53Service,
		Now:             time.Now().UTC(),
		BodyHashHex:     hex.EncodeToString(bodyHashBytes[:]),
	})
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, parseRoute53Error(resp.StatusCode, respBody)
	}
	return respBody, nil
}

type route53ErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

type route53InvalidErrorResponse struct {
	XMLName xml.Name `xml:"InvalidChangeBatch"`
	Messages struct {
		Messages []string `xml:"Message"`
	} `xml:"Messages"`
}

func parseRoute53Error(status int, body []byte) error {
	var parsed route53ErrorResponse
	if err := xml.Unmarshal(body, &parsed); err == nil && parsed.Error.Code != "" {
		return fmt.Errorf("route53 %s: %s", parsed.Error.Code, parsed.Error.Message)
	}
	var invalidParsed route53InvalidErrorResponse
	if err := xml.Unmarshal(body, &invalidParsed); err == nil && len(invalidParsed.Messages.Messages) > 0 {
		return fmt.Errorf("route53 InvalidChangeBatch: %s", strings.Join(invalidParsed.Messages.Messages, "; "))
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return fmt.Errorf("route53 request failed with HTTP %d", status)
	}
	return fmt.Errorf("route53 request failed with HTTP %d: %s", status, trimmed)
}

