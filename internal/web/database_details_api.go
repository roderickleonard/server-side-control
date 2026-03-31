package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaganyegin/server-side-control/internal/auth"
	"github.com/kaganyegin/server-side-control/internal/domain"
	"github.com/kaganyegin/server-side-control/internal/system"
)

func (a *App) handleDatabaseDetailsPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	databaseName := strings.TrimSpace(r.URL.Query().Get("name"))
	selectedTable := strings.TrimSpace(r.URL.Query().Get("table"))
	details, err := a.databases.InspectDatabase(system.DatabaseInspectSpec{DatabaseName: databaseName, TableName: selectedTable, Limit: 100})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": databaseDetailErrorMessage(err)})
		return
	}
	var selectedSummary *system.DatabaseTableSummary
	for index := range details.Tables {
		if details.Tables[index].Name == details.SelectedTable {
			selectedSummary = &details.Tables[index]
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"preview": details.Preview,
		"selected_table": details.SelectedTable,
		"table_summary": selectedSummary,
		"approximate_size": details.ApproximateSizeDisplay,
	})
}

func (a *App) handleDatabaseDetailsQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form payload"})
		return
	}
	databaseName := strings.TrimSpace(r.FormValue("database_name"))
	querySQL := strings.TrimSpace(r.FormValue("query_sql"))
	if databaseName == "" || querySQL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "database name and query are required"})
		return
	}
	var result system.DatabaseQueryResult
	var err error
	if a.helper != nil {
		_, err = a.helper.Call(r.Context(), "mysql.execute_query", map[string]any{"database_name": databaseName, "query_sql": querySQL, "max_rows": 250}, &result)
	} else {
		result, err = system.ExecuteDatabaseQuery(a.cfg.MySQLAdminDefaultsFile, databaseName, querySQL, 250)
	}
	if err != nil {
		a.recordAudit(r.Context(), "database.query", databaseName, "failure", map[string]any{"error": err.Error(), "query": auditQueryPreview(querySQL)})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": databaseDetailErrorMessage(err)})
		return
	}
	identity, _ := auth.IdentityFromContext(r.Context())
	actor := databaseName
	if identity.Username != "" {
		actor = identity.Username
	}
	_ = actor
	result.Message = firstNonEmpty(result.Message, "Query executed successfully.")
	a.recordAudit(r.Context(), "database.query", databaseName, "success", map[string]any{"query": auditQueryPreview(querySQL), "rows": result.RowCount, "truncated": result.Truncated})
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleDatabaseBackupDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/databases/details/download/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	entry, err := a.store.GetDatabaseBackupToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if entry.DownloadedAt != nil || time.Now().After(entry.ExpiresAt) {
		_ = os.Remove(entry.FilePath)
		_ = a.store.DeleteDatabaseBackupToken(r.Context(), token)
		http.Error(w, "download link expired", http.StatusGone)
		return
	}
	file, err := os.Open(entry.FilePath)
	if err != nil {
		_ = a.store.DeleteDatabaseBackupToken(r.Context(), token)
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	filename := fmt.Sprintf("%s-backup-%s.sql.gz", entry.DatabaseName, time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	if _, err := io.Copy(w, file); err != nil {
		return
	}
	now := time.Now().UTC()
	_ = a.store.MarkDatabaseBackupDownloaded(r.Context(), token, now)
	_ = a.store.DeleteDatabaseBackupToken(r.Context(), token)
	_ = os.Remove(entry.FilePath)
}

func (a *App) generateAndEmailDatabaseBackup(ctx context.Context, databaseName string, recipient string) error {
	if a.store == nil {
		return errors.New("database backup tokens are unavailable because the panel store is not configured")
	}
	token, err := randomPassword(40)
	if err != nil {
		return err
	}
	safeDatabaseName := strings.ReplaceAll(databaseName, "_", "-")
	backupPath := filepath.Join(os.TempDir(), fmt.Sprintf("ssc-db-backup-%s-%s.sql.gz", safeDatabaseName, token[:12]))
	if a.helper != nil {
		var exportResult struct {
			FilePath string `json:"file_path"`
		}
		if _, err := a.helper.Call(ctx, "mysql.export_database", map[string]any{"database_name": databaseName, "file_path": backupPath}, &exportResult); err != nil {
			return err
		}
		if strings.TrimSpace(exportResult.FilePath) != "" {
			backupPath = exportResult.FilePath
		}
	} else {
		if _, err := system.ExportDatabase(a.cfg.MySQLAdminDefaultsFile, databaseName, backupPath); err != nil {
			return err
		}
	}
	identity, _ := auth.IdentityFromContext(ctx)
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	if err := a.store.SaveDatabaseBackupToken(ctx, domain.DatabaseBackupToken{
		Token: token,
		DatabaseName: databaseName,
		RecipientEmail: recipient,
		FilePath: backupPath,
		CreatedBy: identity.Username,
		ExpiresAt: expiresAt,
	}); err != nil {
		_ = os.Remove(backupPath)
		return err
	}
	if err := sendDatabaseBackupReadyEmail(a.cfg, databaseName, recipient, strings.TrimRight(a.cfg.BaseURL, "/")+"/databases/details/download/"+token, expiresAt); err != nil {
		_ = os.Remove(backupPath)
		_ = a.store.DeleteDatabaseBackupToken(ctx, token)
		return err
	}
	return nil
}

func (a *App) startDatabaseBackupCleanup(ctx context.Context) {
	if a.store == nil {
		return
	}
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.cleanupExpiredDatabaseBackups(ctx)
			}
		}
	}()
}

func (a *App) cleanupExpiredDatabaseBackups(ctx context.Context) {
	if a.store == nil {
		return
	}
	entries, err := a.store.ListExpiredDatabaseBackupTokens(ctx, time.Now().UTC())
	if err != nil {
		return
	}
	for _, entry := range entries {
		_ = os.Remove(entry.FilePath)
		_ = a.store.DeleteDatabaseBackupToken(ctx, entry.Token)
	}
}

func auditQueryPreview(query string) string {
	query = strings.TrimSpace(query)
	if len(query) <= 180 {
		return query
	}
	return query[:180] + "..."
}