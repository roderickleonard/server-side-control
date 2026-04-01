CREATE TABLE IF NOT EXISTS panel_users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    linux_user VARCHAR(191) NOT NULL UNIQUE,
    role VARCHAR(64) NOT NULL DEFAULT 'operator',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS managed_sites (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(191) NOT NULL,
    owner_linux_user VARCHAR(191) NOT NULL,
    domain_name VARCHAR(191) NOT NULL,
    root_directory VARCHAR(255) NOT NULL,
    laravel_extra_writable_paths VARCHAR(2048) NOT NULL DEFAULT '',
    runtime VARCHAR(64) NOT NULL,
    upstream_url VARCHAR(255) NOT NULL DEFAULT '',
    php_version VARCHAR(32) NOT NULL DEFAULT '',
    nginx_config_path VARCHAR(255) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deployments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    site_id BIGINT NULL,
    repository_url VARCHAR(255) NOT NULL,
    branch_name VARCHAR(191) NOT NULL DEFAULT 'main',
    target_directory VARCHAR(255) NOT NULL,
    run_as_user VARCHAR(191) NOT NULL,
    last_status VARCHAR(64) NOT NULL DEFAULT 'pending',
    last_output TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor VARCHAR(191) NOT NULL,
    action VARCHAR(191) NOT NULL,
    target VARCHAR(255) NOT NULL,
    outcome VARCHAR(64) NOT NULL,
    metadata JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS site_subdomains (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    site_id BIGINT NOT NULL,
    subdomain VARCHAR(191) NOT NULL,
    full_domain VARCHAR(255) NOT NULL,
    laravel_extra_writable_paths VARCHAR(2048) NOT NULL DEFAULT '',
    runtime VARCHAR(32) NOT NULL,
    upstream_url VARCHAR(255) NOT NULL DEFAULT '',
    php_version VARCHAR(32) NOT NULL DEFAULT '',
    node_version VARCHAR(64) NOT NULL DEFAULT '',
    repository_url VARCHAR(255) NOT NULL DEFAULT '',
    branch_name VARCHAR(191) NOT NULL DEFAULT '',
    git_credential_protocol VARCHAR(32) NOT NULL DEFAULT '',
    git_credential_username VARCHAR(191) NOT NULL DEFAULT '',
    post_deploy_command TEXT NOT NULL,
    auto_deploy_enabled TINYINT(1) NOT NULL DEFAULT 0,
    auto_deploy_branch VARCHAR(191) NOT NULL DEFAULT '',
    auto_deploy_secret VARCHAR(255) NOT NULL DEFAULT '',
    auto_deploy_command TEXT NOT NULL,
    auto_deploy_node_version VARCHAR(64) NOT NULL DEFAULT '',
    auto_deploy_notify_email VARCHAR(255) NOT NULL DEFAULT '',
    root_directory VARCHAR(255) NOT NULL DEFAULT '',
    nginx_config_path VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_site_subdomains_full_domain (full_domain),
    INDEX idx_site_subdomains_site_id (site_id),
    CONSTRAINT fk_site_subdomains_site FOREIGN KEY (site_id) REFERENCES managed_sites(id) ON DELETE CASCADE
);
