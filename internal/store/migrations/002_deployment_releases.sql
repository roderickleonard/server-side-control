CREATE TABLE IF NOT EXISTS deployment_releases (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    repository_url VARCHAR(255) NOT NULL,
    branch_name VARCHAR(191) NOT NULL DEFAULT 'main',
    target_directory VARCHAR(255) NOT NULL,
    run_as_user VARCHAR(191) NOT NULL,
    action VARCHAR(64) NOT NULL,
    status VARCHAR(64) NOT NULL,
    commit_sha VARCHAR(64) NOT NULL DEFAULT '',
    previous_commit_sha VARCHAR(64) NOT NULL DEFAULT '',
    output LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_deployment_releases_target_directory (target_directory),
    INDEX idx_deployment_releases_created_at (created_at)
);
