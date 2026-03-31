CREATE TABLE IF NOT EXISTS database_backup_tokens (
    token VARCHAR(96) PRIMARY KEY,
    database_name VARCHAR(191) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    created_by VARCHAR(191) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    downloaded_at DATETIME NULL
);