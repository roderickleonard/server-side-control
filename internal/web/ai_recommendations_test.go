package web

import (
	"encoding/json"
	"testing"
)

func TestServiceAIResponseUnmarshalAcceptsNumericLongQueryTime(t *testing.T) {
	payload := []byte(`{
		"summary": "Tune MySQL conservatively.",
		"recommendations_markdown": "- Increase buffer pool.\n- Enable slow query logging.",
		"suggested_mysql_config": {
			"max_connections": 200,
			"max_user_connections": 30,
			"wait_timeout": 600,
			"interactive_timeout": 600,
			"max_connect_errors": 100,
			"thread_cache_size": 16,
			"table_open_cache": 2048,
			"innodb_buffer_pool_size_mb": 1024,
			"port": 3306,
			"bind_address": "127.0.0.1",
			"slow_query_log_enabled": true,
			"slow_query_log_file": "/var/log/mysql/slow.log",
			"long_query_time_seconds": 2.5
		}
	}`)

	var result serviceAIResponse
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal service AI response: %v", err)
	}
	if result.SuggestedMySQLConfig == nil {
		t.Fatal("expected suggested mysql config")
	}
	if got := result.SuggestedMySQLConfig.LongQueryTimeSeconds; got != "2.5" {
		t.Fatalf("long query time = %q, want %q", got, "2.5")
	}
	if got := result.SuggestedMySQLConfig.MaxConnections; got != 200 {
		t.Fatalf("max connections = %d, want %d", got, 200)
	}
	if got := result.SuggestedMySQLConfig.SlowQueryLogEnabled; !got {
		t.Fatal("slow query log enabled = false, want true")
	}
}

func TestServiceAIResponseUnmarshalAcceptsQuotedScalars(t *testing.T) {
	payload := []byte(`{
		"summary": "OK",
		"recommendations_markdown": "- Review current values.",
		"suggested_mysql_config": {
			"max_connections": "250",
			"max_user_connections": "40",
			"wait_timeout": "900",
			"interactive_timeout": "900",
			"max_connect_errors": "100",
			"thread_cache_size": "32",
			"table_open_cache": "4096",
			"innodb_buffer_pool_size_mb": "2048",
			"port": "3306",
			"bind_address": "0.0.0.0",
			"slow_query_log_enabled": "true",
			"slow_query_log_file": "/var/log/mysql/mysql-slow.log",
			"long_query_time_seconds": "1"
		}
	}`)

	var result serviceAIResponse
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal service AI response: %v", err)
	}
	if result.SuggestedMySQLConfig == nil {
		t.Fatal("expected suggested mysql config")
	}
	if got := result.SuggestedMySQLConfig.Port; got != 3306 {
		t.Fatalf("port = %d, want %d", got, 3306)
	}
	if got := result.SuggestedMySQLConfig.LongQueryTimeSeconds; got != "1" {
		t.Fatalf("long query time = %q, want %q", got, "1")
	}
	if got := result.SuggestedMySQLConfig.SlowQueryLogEnabled; !got {
		t.Fatal("slow query log enabled = false, want true")
	}
}
