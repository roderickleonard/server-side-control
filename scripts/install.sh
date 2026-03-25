#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
ENV_FILE="/etc/server-side-control/panel.env"
INSTALL_STATE_FILE="/etc/server-side-control/install-state.env"
UNIT_FILE="/etc/systemd/system/server-side-control.service"
BINARY_PATH="/usr/local/bin/server-side-control"
INSTALLER_PATH="/usr/local/bin/server-side-control-installer"
HELPER_PATH="/usr/local/bin/server-side-control-helper"
UPDATER_PATH="/usr/local/bin/server-side-control-update"
SUDOERS_PATH="/etc/sudoers.d/server-side-control-helper"
SERVICE_USER="server-side-control"
GO_VERSION="1.22.5"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
APT_UPDATED=0
SKIP_INSTALLER="${SSC_SKIP_INSTALLER:-0}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this installer as root on the Ubuntu target host."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

write_install_state() {
    local git_remote=""
    local git_branch=""

    if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git_remote="$(git -C "$ROOT_DIR" remote get-url origin 2>/dev/null || true)"
        git_branch="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    fi

    cat >"$INSTALL_STATE_FILE" <<EOF
INSTALL_ROOT=$(printf '%q' "$ROOT_DIR")
GIT_REMOTE=$(printf '%q' "$git_remote")
GIT_BRANCH=$(printf '%q' "$git_branch")
EOF
    chmod 600 "$INSTALL_STATE_FILE"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

ensure_apt_update() {
    if [[ "$APT_UPDATED" -eq 0 ]]; then
        apt-get update
        APT_UPDATED=1
    fi
}

ensure_apt_package() {
    local package="$1"
    if dpkg -s "$package" >/dev/null 2>&1; then
        echo "Skipping apt package $package (already installed)"
        return
    fi

    ensure_apt_update
    apt-get install -y "$package"
}

ensure_optional_apt_package() {
    local package="$1"
    if dpkg -s "$package" >/dev/null 2>&1; then
        echo "Skipping optional apt package $package (already installed)"
        return
    fi
    if ! apt-cache show "$package" >/dev/null 2>&1; then
        echo "Skipping optional apt package $package (not available in apt sources)"
        return
    fi

    ensure_apt_update
    apt-get install -y "$package"
}

ensure_go() {
    if command_exists go; then
        local current_version
        current_version="$(go version | awk '{print $3}')"
        if [[ "$current_version" =~ ^go1\.(2[2-9]|[3-9][0-9]) ]]; then
            echo "Skipping Go install ($current_version already available)"
            return
        fi
        echo "Existing Go version $current_version is below required 1.22; upgrading"
    fi

    ensure_apt_package curl
    local download_path="/tmp/${GO_TARBALL}"
    curl -fsSL "$GO_URL" -o "$download_path"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$download_path"
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
}

ensure_go_modules() {
    echo "Downloading Go module dependencies"
    GOTOOLCHAIN=local GOFLAGS=-mod=mod go mod download all
}

ensure_pm2() {
    if command_exists pm2; then
        echo "Skipping PM2 install ($(pm2 -v 2>/dev/null || echo installed) already available)"
        return
    fi

    ensure_apt_package nodejs
    ensure_apt_package npm
    npm install -g pm2
}

ensure_base_dependencies() {
    local packages=(
        git
        curl
        ca-certificates
        build-essential
        nginx
        mysql-server
        certbot
        python3-certbot-nginx
        sudo
    )

    local package
    for package in "${packages[@]}"; do
        ensure_apt_package "$package"
    done

    ensure_optional_apt_package php8.2-fpm
    ensure_optional_apt_package php8.3-fpm
}

ensure_base_dependencies
ensure_go
ensure_go_modules
ensure_pm2
systemctl enable --now mysql

mkdir -p "$BUILD_DIR"

go build -o "$BUILD_DIR/server-side-control" ./cmd/panel
go build -o "$BUILD_DIR/server-side-control-installer" ./cmd/installer
go build -o "$BUILD_DIR/server-side-control-helper" ./cmd/helper

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/server-side-control --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -Dm755 "$BUILD_DIR/server-side-control" "$BINARY_PATH"
install -Dm755 "$BUILD_DIR/server-side-control-installer" "$INSTALLER_PATH"
install -Dm755 "$BUILD_DIR/server-side-control-helper" "$HELPER_PATH"
install -Dm755 "$ROOT_DIR/scripts/update.sh" "$UPDATER_PATH"
install -Dm644 "$ROOT_DIR/deploy/systemd/server-side-control.service" "$UNIT_FILE"
install -Dm440 "$ROOT_DIR/deploy/sudoers/server-side-control-helper" "$SUDOERS_PATH"
mkdir -p /etc/server-side-control
write_install_state

if [[ "$SKIP_INSTALLER" == "1" ]]; then
    if [[ ! -f "$ENV_FILE" ]]; then
        echo "SSC_SKIP_INSTALLER=1 was set but $ENV_FILE does not exist."
        exit 1
    fi
    echo "Skipping installer questions and reusing existing configuration from $ENV_FILE"
else
    PANEL_ENV_FILE="$ENV_FILE" "$INSTALLER_PATH"
fi

chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

systemctl daemon-reload
systemctl enable --now server-side-control

printf '\nInstalled. Open the panel at the configured base URL.\n'
