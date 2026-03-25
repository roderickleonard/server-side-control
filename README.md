# Server Side Control

Server Side Control is a Go-based Ubuntu control panel for single-server operations. The current implementation now includes session-based login, Linux user provisioning, MySQL schema bootstrap, MySQL database/user provisioning, Nginx site generation with validation and reload, Certbot-based TLS automation, Git-based deploy execution under a selected Linux user, PM2 process inspection with start/stop/restart/reload/log access, PHP-FPM version switching for managed sites, audit logging, helper-based privilege separation, helper action hardening, basic automated tests, HTTP service startup, and live Linux metrics on the dashboard.

## Current implementation status

Implemented now:
- Go HTTP panel with graceful shutdown
- Interactive installer that writes an env file
- Session-based login screen
- PAM-backed Linux authentication on Ubuntu with bootstrap fallback
- Automatic MySQL migration runner on startup
- Ubuntu/Linux metrics collection for the dashboard
- Linux user creation with optional home directory provisioning
- MySQL database and scoped user provisioning
- Nginx site generation for reverse proxy, static, and PHP-FPM modes with validation and reload
- Certbot-based TLS issuance from the Sites screen
- Git clone/update deploy flow with optional post-deploy command execution under the selected Linux user
- Deploy rollback to a recorded commit with release history metadata
- PM2 process listing, start, stop, restart, reload, and bounded log viewing under the owning Linux user
- PHP-FPM version switching for managed sites via stored Nginx config paths
- Audit log history page for recent privileged operations and outcomes
- Dedicated root helper binary with sudoers-based privilege delegation while the panel service runs as a non-root user
- Helper action whitelist and payload-size validation in the root helper
- Basic automated tests for helper validation and Nginx config rendering

Planned next:
- Richer Nginx editing flows
- Per-user PHP profile defaults beyond site-specific switching
- Audit filtering and role-based authorization

## Project layout

- `cmd/panel`: main HTTP service
- `cmd/installer`: interactive bootstrap CLI
- `internal/config`: env-backed configuration loader
- `internal/store`: MySQL connectivity and migrations
- `internal/system`: system-facing adapters and Linux metrics
- `internal/web`: HTTP handlers, templates, middleware, static assets
- `deploy/systemd`: unit file for Ubuntu deployment
- `scripts/install.sh`: root installer entrypoint for Ubuntu
- `scripts/update.sh`: repo-based updater that pulls from git and re-runs install without re-asking config questions

## Quick start on Ubuntu

1. Clone the repository.
2. Run `sudo ./scripts/install.sh`.
3. Let the installer auto-install missing Ubuntu packages, Go, and PM2.
4. Answer the installer questions.
5. Open the configured base URL and log in with the bootstrap credentials.

## Updating on Ubuntu

After the first install, you can update the panel directly from the cloned repository source:

1. Run `sudo /usr/local/bin/server-side-control-update`
2. The updater reads the saved install state, fetches the latest code from the same git branch, runs `git pull --ff-only`, rebuilds the binaries, and restarts the service.
3. Existing panel configuration in `/etc/server-side-control/panel.env` is reused, so the installer does not ask the setup questions again during updates.

## Environment variables

The installer writes these values to `panel.env`:
- `PANEL_APP_NAME`
- `PANEL_ENV`
- `PANEL_LISTEN_ADDR`
- `PANEL_BASE_URL`
- `PANEL_DATABASE_DSN`
- `PANEL_BOOTSTRAP_USER`
- `PANEL_BOOTSTRAP_PASSWORD`
- `PANEL_PAM_SERVICE`
- `PANEL_SESSION_COOKIE_NAME`
- `PANEL_MYSQL_ADMIN_DEFAULTS_FILE`
- `PANEL_NGINX_BINARY`
- `PANEL_NGINX_AVAILABLE_DIR`
- `PANEL_NGINX_ENABLED_DIR`
- `PANEL_CERTBOT_BINARY`
- `PANEL_HELPER_BINARY`

## Notes

- The panel systemd unit now runs as the dedicated `server-side-control` user. Privileged operations are delegated to `/usr/local/bin/server-side-control-helper` through `/etc/sudoers.d/server-side-control-helper`.
- The install script is idempotent for dependency bootstrap: it skips apt packages, Go, and PM2 when they are already installed.
- The install script writes `/etc/server-side-control/install-state.env` so the updater knows which repository path and branch to pull from later.
- The installer now asks for MySQL root/admin access, creates the panel database and panel MySQL user automatically, writes the panel DSN into `panel.env`, and stores the MySQL admin credentials in a root-only defaults file.
- PAM support depends on the Ubuntu target host exposing libpam and a working PAM service such as `login`.
- MySQL tables are created automatically during startup if the DSN is reachable.
- Database provisioning from the panel runs through the privileged helper and the saved MySQL admin defaults file instead of assuming the panel DSN has global MySQL privileges.
- The Databases page can also rotate the saved MySQL admin password; when left blank, it generates a new secret, updates MySQL through the helper, and rewrites the root-only defaults file.
- Nginx site application writes the vhost, runs `nginx -t`, and reloads only if validation succeeds; otherwise it rolls back the attempted change.
- TLS automation uses `certbot --nginx` through the privileged helper and then re-validates Nginx before reload.
- Deploy actions run through `sudo -u <user>` for git operations; optional post-deploy commands currently run via `sh -lc` under that user and should be treated as privileged operator input.
- Successful deploys and rollbacks are written into `deployment_releases` with current and previous commit metadata for history tracking.
- PM2 actions also run under `sudo -u <user>`; log viewing uses `pm2 logs --nostream --lines <n>` to keep responses bounded.
- PHP switching edits the managed site's stored Nginx config, validates the config, and reloads Nginx only on success.
- Audit logs are stored in MySQL and exposed through the `Logs` page when `PANEL_DATABASE_DSN` is configured.
