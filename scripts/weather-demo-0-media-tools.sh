#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Only disposable presentation jobs; never change /etc/apt or the development host.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
test "${RUNNER_OS:-}" = Linux
test "${GITHUB_REPOSITORY:-}" = VOLPAROSSA/volparossa
test "$(id -u)" != 0
test -d "$GITHUB_WORKSPACE/.git"
printf '%s\n' 'Disposable hosted runner: install ffmpeg/fonts from signed Ubuntu noble archives; temporary workspace sources only; unchanged 180s/300s limits.'
mkdir -p "$GITHUB_WORKSPACE/.cache"
media_sources_dir=$(mktemp -d "$GITHUB_WORKSPACE/.cache/weather-media-apt.XXXXXX")
cleanup() {
  rm -f -- "$media_sources_dir/ubuntu.sources" "$media_sources_dir/empty.list"
  rmdir -- "$media_sources_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Ubuntu's archive keys and apt-secure remain mandatory. No trusted=yes or
# third-party repository. See https://ubuntu.com/server/docs/how-to/software/package-management/
cat > "$media_sources_dir/ubuntu.sources" <<'SOURCES'
Types: deb
URIs: https://archive.ubuntu.com/ubuntu
Suites: noble noble-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES
touch "$media_sources_dir/empty.list"
media_apt_options=(-o "Dir::Etc::sourcelist=$media_sources_dir/empty.list"
  -o "Dir::Etc::sourceparts=$media_sources_dir" -o APT::Get::List-Cleanup=0)
timeout 180s sudo -n env DEBIAN_FRONTEND=noninteractive apt-get "${media_apt_options[@]}" update
timeout 300s sudo -n env DEBIAN_FRONTEND=noninteractive apt-get "${media_apt_options[@]}" \
  install --yes --no-install-recommends ffmpeg fonts-dejavu-core
