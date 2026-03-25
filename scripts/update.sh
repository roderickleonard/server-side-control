#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="/etc/server-side-control/install-state.env"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this updater as root on the Ubuntu target host."
    exit 1
fi

if [[ ! -f "$STATE_FILE" ]]; then
    echo "Install state file not found: $STATE_FILE"
    echo "Run the initial installer first."
    exit 1
fi

source "$STATE_FILE"

if [[ -z "${INSTALL_ROOT:-}" ]]; then
    echo "INSTALL_ROOT is missing in $STATE_FILE"
    exit 1
fi

if [[ ! -d "$INSTALL_ROOT/.git" ]]; then
    echo "Git repository not found in $INSTALL_ROOT"
    exit 1
fi

if ! git -C "$INSTALL_ROOT" diff --quiet || ! git -C "$INSTALL_ROOT" diff --cached --quiet; then
    echo "Repository has uncommitted changes in $INSTALL_ROOT"
    echo "Commit, stash, or discard them before running the updater."
    exit 1
fi

BRANCH="${SSC_UPDATE_BRANCH:-${GIT_BRANCH:-}}"
if [[ -z "$BRANCH" || "$BRANCH" == "HEAD" ]]; then
    BRANCH="$(git -C "$INSTALL_ROOT" rev-parse --abbrev-ref HEAD)"
fi

echo "Updating Server Side Control from $INSTALL_ROOT"
echo "Target branch: $BRANCH"

git -C "$INSTALL_ROOT" fetch --tags origin
git -C "$INSTALL_ROOT" checkout "$BRANCH"
git -C "$INSTALL_ROOT" pull --ff-only origin "$BRANCH"

echo "Re-running installer in reuse-config mode"
SSC_SKIP_INSTALLER=1 "$INSTALL_ROOT/scripts/install.sh"

echo
echo "Update completed successfully."