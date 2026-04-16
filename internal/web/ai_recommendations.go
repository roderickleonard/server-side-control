package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kaganyegin/server-side-control/internal/system"
)

type serviceAIResponse struct {
	Summary              string                         `json:"summary"`
	Recommendations      string                         `json:"recommendations_markdown"`
	SuggestedMySQLConfig *system.MySQLServiceConfigSpec `json:"suggested_mysql_config,omitempty"`
}

func (r *serviceAIResponse) UnmarshalJSON(data []byte) error {
	type rawServiceAIResponse struct {
		Summary              string                 `json:"summary"`
		Recommendations      string                 `json:"recommendations_markdown"`
		SuggestedMySQLConfig *openAIMySQLConfigSpec `json:"suggested_mysql_config,omitempty"`
	}

	var raw rawServiceAIResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	r.Summary = raw.Summary
	r.Recommendations = raw.Recommendations
	r.SuggestedMySQLConfig = nil
	if raw.SuggestedMySQLConfig != nil {
		spec := raw.SuggestedMySQLConfig.toSystemSpec()
		r.SuggestedMySQLConfig = &spec
	}
	return nil
}

type openAIMySQLConfigSpec struct {
	MaxConnections         flexibleJSONInt    `json:"max_connections"`
	MaxUserConnections     flexibleJSONInt    `json:"max_user_connections"`
	WaitTimeout            flexibleJSONInt    `json:"wait_timeout"`
	InteractiveTimeout     flexibleJSONInt    `json:"interactive_timeout"`
	MaxConnectErrors       flexibleJSONInt    `json:"max_connect_errors"`
	ThreadCacheSize        flexibleJSONInt    `json:"thread_cache_size"`
	TableOpenCache         flexibleJSONInt    `json:"table_open_cache"`
	InnodbBufferPoolSizeMB flexibleJSONInt    `json:"innodb_buffer_pool_size_mb"`
	Port                   flexibleJSONInt    `json:"port"`
	BindAddress            string             `json:"bind_address"`
	SlowQueryLogEnabled    flexibleJSONBool   `json:"slow_query_log_enabled"`
	SlowQueryLogFile       string             `json:"slow_query_log_file"`
	LongQueryTimeSeconds   flexibleJSONString `json:"long_query_time_seconds"`
}

func (s openAIMySQLConfigSpec) toSystemSpec() system.MySQLServiceConfigSpec {
	return system.MySQLServiceConfigSpec{
		MaxConnections:         int(s.MaxConnections),
		MaxUserConnections:     int(s.MaxUserConnections),
		WaitTimeout:            int(s.WaitTimeout),
		InteractiveTimeout:     int(s.InteractiveTimeout),
		MaxConnectErrors:       int(s.MaxConnectErrors),
		ThreadCacheSize:        int(s.ThreadCacheSize),
		TableOpenCache:         int(s.TableOpenCache),
		InnodbBufferPoolSizeMB: int(s.InnodbBufferPoolSizeMB),
		Port:                   int(s.Port),
		BindAddress:            s.BindAddress,
		SlowQueryLogEnabled:    bool(s.SlowQueryLogEnabled),
		SlowQueryLogFile:       s.SlowQueryLogFile,
		LongQueryTimeSeconds:   string(s.LongQueryTimeSeconds),
	}
}

type flexibleJSONInt int

func (v *flexibleJSONInt) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		return nil
	}

	var number json.Number
	if err := json.Unmarshal(data, &number); err == nil {
		parsed, err := strconv.Atoi(number.String())
		if err == nil {
			*v = flexibleJSONInt(parsed)
			return nil
		}
		floatValue, floatErr := strconv.ParseFloat(number.String(), 64)
		if floatErr != nil || floatValue != float64(int(floatValue)) {
			return fmt.Errorf("invalid integer value %q", number.String())
		}
		*v = flexibleJSONInt(int(floatValue))
		return nil
	}

	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err != nil {
		return fmt.Errorf("decode integer value: %w", err)
	}
	stringValue = strings.TrimSpace(stringValue)
	if stringValue == "" {
		return nil
	}
	parsed, err := strconv.Atoi(stringValue)
	if err == nil {
		*v = flexibleJSONInt(parsed)
		return nil
	}
	floatValue, floatErr := strconv.ParseFloat(stringValue, 64)
	if floatErr != nil || floatValue != float64(int(floatValue)) {
		return fmt.Errorf("invalid integer value %q", stringValue)
	}
	*v = flexibleJSONInt(int(floatValue))
	return nil
}

type flexibleJSONBool bool

func (v *flexibleJSONBool) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		return nil
	}

	var boolValue bool
	if err := json.Unmarshal(data, &boolValue); err == nil {
		*v = flexibleJSONBool(boolValue)
		return nil
	}

	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err != nil {
		return fmt.Errorf("decode boolean value: %w", err)
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(stringValue))
	if err != nil {
		return fmt.Errorf("invalid boolean value %q", stringValue)
	}
	*v = flexibleJSONBool(parsed)
	return nil
}

type flexibleJSONString string

func (v *flexibleJSONString) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		return nil
	}

	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err == nil {
		*v = flexibleJSONString(stringValue)
		return nil
	}

	var number json.Number
	if err := json.Unmarshal(data, &number); err == nil {
		*v = flexibleJSONString(number.String())
		return nil
	}

	return fmt.Errorf("decode string value from %s", text)
}

type openAIChatRequest struct {
	Model          string                `json:"model"`
	Messages       []openAIChatMessage   `json:"messages"`
	Temperature    float64               `json:"temperature,omitempty"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIResponseFormat struct {
	Type string `json:"type"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (a *App) openAIConfigured() bool {
	return strings.TrimSpace(a.cfg.OpenAIAPIKey) != ""
}

func (a *App) requestServiceAIRecommendation(ctx context.Context, serviceName string, snapshot any, wantMySQLConfig bool) (serviceAIResponse, error) {
	if !a.openAIConfigured() {
		return serviceAIResponse{}, fmt.Errorf("OpenAI secret is not configured yet. Save PANEL_OPENAI_API_KEY in Settings first")
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return serviceAIResponse{}, err
	}
	instruction := "Return strict JSON with fields: summary, recommendations_markdown"
	if wantMySQLConfig {
		instruction += `, suggested_mysql_config. In suggested_mysql_config include every field exactly as JSON keys: max_connections, max_user_connections, wait_timeout, interactive_timeout, max_connect_errors, thread_cache_size, table_open_cache, innodb_buffer_pool_size_mb, port, bind_address, slow_query_log_enabled, slow_query_log_file, long_query_time_seconds.`
		instruction += " Only include suggested_mysql_config when you are confident enough to recommend concrete values."
	} else {
		instruction += ". Do not include extra top-level keys."
	}
	prompt := strings.Join([]string{
		"You are an infrastructure tuning assistant for a server control panel.",
		"Analyze the service snapshot and produce short, practical recommendations.",
		"Prefer conservative, production-safe changes. Mention risks and when no change is needed.",
		instruction,
		"Service: " + serviceName,
		"Snapshot:",
		string(payload),
	}, "\n\n")
	requestBody := openAIChatRequest{
		Model: firstNonEmpty(strings.TrimSpace(a.cfg.OpenAIModel), "gpt-4.1-mini"),
		Messages: []openAIChatMessage{
			{Role: "system", Content: "You are a precise Linux service tuning assistant. Return valid JSON only."},
			{Role: "user", Content: prompt},
		},
		Temperature:    0.2,
		ResponseFormat: &openAIResponseFormat{Type: "json_object"},
	}
	encodedBody, err := json.Marshal(requestBody)
	if err != nil {
		return serviceAIResponse{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(encodedBody))
	if err != nil {
		return serviceAIResponse{}, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(a.cfg.OpenAIAPIKey))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 45 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return serviceAIResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return serviceAIResponse{}, err
	}
	var parsed openAIChatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return serviceAIResponse{}, fmt.Errorf("decode OpenAI response: %w", err)
	}
	if parsed.Error != nil {
		return serviceAIResponse{}, fmt.Errorf("OpenAI API error: %s", strings.TrimSpace(parsed.Error.Message))
	}
	if response.StatusCode >= 300 {
		return serviceAIResponse{}, fmt.Errorf("OpenAI request failed with status %s", response.Status)
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		return serviceAIResponse{}, fmt.Errorf("OpenAI returned no recommendation")
	}
	var result serviceAIResponse
	if err := json.Unmarshal([]byte(parsed.Choices[0].Message.Content), &result); err != nil {
		return serviceAIResponse{}, fmt.Errorf("decode OpenAI recommendation payload: %w", err)
	}
	result.Summary = strings.TrimSpace(result.Summary)
	result.Recommendations = strings.TrimSpace(result.Recommendations)
	return result, nil
}

func mysqlAIConfigReady(spec *system.MySQLServiceConfigSpec) bool {
	if spec == nil {
		return false
	}
	if spec.MaxConnections <= 0 || spec.MaxUserConnections < 0 || spec.WaitTimeout <= 0 || spec.InteractiveTimeout <= 0 || spec.MaxConnectErrors <= 0 || spec.ThreadCacheSize < 0 || spec.TableOpenCache <= 0 || spec.InnodbBufferPoolSizeMB <= 0 || spec.Port <= 0 {
		return false
	}
	if strings.TrimSpace(spec.BindAddress) == "" || strings.TrimSpace(spec.LongQueryTimeSeconds) == "" {
		return false
	}
	if spec.SlowQueryLogEnabled && strings.TrimSpace(spec.SlowQueryLogFile) == "" {
		return false
	}
	return true
}

func applyAIRecommendation(data *TemplateData, result serviceAIResponse) {
	data.AIRecommendationSummary = strings.TrimSpace(result.Summary)
	data.AIRecommendation = strings.TrimSpace(result.Recommendations)
	data.MySQLAIPreviewChanges = nil
	if mysqlAIConfigReady(result.SuggestedMySQLConfig) {
		data.MySQLAISuggestionReady = true
		data.MySQLAISuggestedConfig = *result.SuggestedMySQLConfig
		data.MySQLAIPreviewChanges = mySQLAIConfigPreviewChanges(data.MySQLServiceStatus, *result.SuggestedMySQLConfig)
	}
}

func applyMySQLServiceConfigToTemplateData(data *TemplateData, spec system.MySQLServiceConfigSpec) {
	data.MySQLMaxConnections = strconv.Itoa(spec.MaxConnections)
	data.MySQLMaxUserConnections = strconv.Itoa(spec.MaxUserConnections)
	data.MySQLWaitTimeout = strconv.Itoa(spec.WaitTimeout)
	data.MySQLInteractiveTimeout = strconv.Itoa(spec.InteractiveTimeout)
	data.MySQLMaxConnectErrors = strconv.Itoa(spec.MaxConnectErrors)
	data.MySQLThreadCacheSize = strconv.Itoa(spec.ThreadCacheSize)
	data.MySQLTableOpenCache = strconv.Itoa(spec.TableOpenCache)
	data.MySQLInnodbBufferPoolSizeMB = strconv.Itoa(spec.InnodbBufferPoolSizeMB)
	data.MySQLPort = strconv.Itoa(spec.Port)
	data.MySQLBindAddress = strings.TrimSpace(spec.BindAddress)
	data.MySQLSlowQueryLogEnabled = spec.SlowQueryLogEnabled
	data.MySQLSlowQueryLogFile = strings.TrimSpace(spec.SlowQueryLogFile)
	data.MySQLLongQueryTime = strings.TrimSpace(spec.LongQueryTimeSeconds)
}

func mysqlAIConfigSpecFromForm(formValue func(string) string) (system.MySQLServiceConfigSpec, error) {
	parseInt := func(fieldName string, label string) (int, error) {
		value, err := strconv.Atoi(strings.TrimSpace(formValue(fieldName)))
		if err != nil {
			return 0, fmt.Errorf("%s from the AI recommendation is invalid", label)
		}
		return value, nil
	}

	maxConnections, err := parseInt("ai_max_connections", "Max connections")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	maxUserConnections, err := parseInt("ai_max_user_connections", "Max user connections")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	waitTimeout, err := parseInt("ai_wait_timeout", "Wait timeout")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	interactiveTimeout, err := parseInt("ai_interactive_timeout", "Interactive timeout")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	maxConnectErrors, err := parseInt("ai_max_connect_errors", "Max connect errors")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	threadCacheSize, err := parseInt("ai_thread_cache_size", "Thread cache size")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	tableOpenCache, err := parseInt("ai_table_open_cache", "Table open cache")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	innodbBufferPoolSizeMB, err := parseInt("ai_innodb_buffer_pool_size_mb", "InnoDB buffer pool size")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}
	port, err := parseInt("ai_port", "MySQL port")
	if err != nil {
		return system.MySQLServiceConfigSpec{}, err
	}

	return system.MySQLServiceConfigSpec{
		MaxConnections:         maxConnections,
		MaxUserConnections:     maxUserConnections,
		WaitTimeout:            waitTimeout,
		InteractiveTimeout:     interactiveTimeout,
		MaxConnectErrors:       maxConnectErrors,
		ThreadCacheSize:        threadCacheSize,
		TableOpenCache:         tableOpenCache,
		InnodbBufferPoolSizeMB: innodbBufferPoolSizeMB,
		Port:                   port,
		BindAddress:            strings.TrimSpace(formValue("ai_bind_address")),
		SlowQueryLogEnabled:    strings.TrimSpace(formValue("ai_slow_query_log_enabled")) == "1",
		SlowQueryLogFile:       strings.TrimSpace(formValue("ai_slow_query_log_file")),
		LongQueryTimeSeconds:   strings.TrimSpace(formValue("ai_long_query_time")),
	}, nil
}

func mysqlAIRecommendationSnapshot(status system.MySQLServiceStatus, entries []system.DatabaseAccess) map[string]any {
	return map[string]any{
		"status":                 status,
		"managed_database_count": len(entries),
	}
}

func mySQLAIConfigPreviewChanges(status system.MySQLServiceStatus, spec system.MySQLServiceConfigSpec) []string {
	changes := make([]string, 0, 12)
	appendChange := func(label string, current string, suggested string) {
		current = strings.TrimSpace(current)
		suggested = strings.TrimSpace(suggested)
		if current == suggested {
			return
		}
		if current == "" {
			current = "-"
		}
		if suggested == "" {
			suggested = "-"
		}
		changes = append(changes, fmt.Sprintf("%s: %s -> %s", label, current, suggested))
	}

	appendChange("Max connections", strconv.Itoa(status.MaxConnections), strconv.Itoa(spec.MaxConnections))
	appendChange("Max user connections", strconv.Itoa(status.MaxUserConnections), strconv.Itoa(spec.MaxUserConnections))
	appendChange("Wait timeout", strconv.Itoa(status.WaitTimeout), strconv.Itoa(spec.WaitTimeout))
	appendChange("Interactive timeout", strconv.Itoa(status.InteractiveTimeout), strconv.Itoa(spec.InteractiveTimeout))
	appendChange("Max connect errors", strconv.Itoa(status.MaxConnectErrors), strconv.Itoa(spec.MaxConnectErrors))
	appendChange("Thread cache size", strconv.Itoa(status.ThreadCacheSize), strconv.Itoa(spec.ThreadCacheSize))
	appendChange("Table open cache", strconv.Itoa(status.TableOpenCache), strconv.Itoa(spec.TableOpenCache))
	appendChange("InnoDB buffer pool (MB)", strconv.FormatInt(status.InnodbBufferPoolSizeBytes/(1024*1024), 10), strconv.Itoa(spec.InnodbBufferPoolSizeMB))
	appendChange("Port", strconv.Itoa(status.Port), strconv.Itoa(spec.Port))
	appendChange("Bind address", status.BindAddress, spec.BindAddress)
	appendChange("Slow query log", boolLabel(status.SlowQueryLogEnabled), boolLabel(spec.SlowQueryLogEnabled))
	appendChange("Slow query log file", status.SlowQueryLogFile, spec.SlowQueryLogFile)
	appendChange("Long query time", status.LongQueryTimeSeconds, spec.LongQueryTimeSeconds)
	return changes
}

func boolLabel(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}

func phpAIRecommendationSnapshot(data TemplateData) map[string]any {
	return map[string]any{
		"installed_versions":   data.PHPVersions,
		"installable_versions": data.PHPInstallableVersions,
		"extension_statuses":   data.PHPExtensionStatuses,
		"ini_settings":         data.PHPINISettings,
		"managed_sites_count":  len(data.ManagedSites),
	}
}

func redisAIRecommendationSnapshot(data TemplateData) map[string]any {
	return map[string]any{
		"status": data.RedisStatus,
		"form_values": map[string]any{
			"username":        data.RedisUsername,
			"port":            data.RedisPort,
			"max_memory_mb":   data.RedisMaxMemoryMB,
			"eviction_policy": data.RedisEvictionPolicy,
		},
	}
}

func supervisorAIRecommendationSnapshot(data TemplateData) map[string]any {
	return map[string]any{
		"status":   data.SupervisorStatus,
		"programs": data.SupervisorPrograms,
		"linux_users": func() []string {
			items := make([]string, 0, len(data.LinuxUsers))
			for _, user := range data.LinuxUsers {
				items = append(items, user.Username)
			}
			return items
		}(),
	}
}
