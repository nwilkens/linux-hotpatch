#!/usr/bin/env bash
# backend_load picks lib/backend/<id>.sh from ID, then ID_LIKE, then the override.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

run() {
	HOTPATCH_OS_RELEASE="$1" HOTPATCH_BACKEND="${2:-}" bash -c '
		source lib/common.sh
		backend_load
		printf "%s" "$HOTPATCH_BACKEND"' 2>/dev/null
}

printf 'ID=ubuntu\nID_LIKE=debian\n' > "$tmp/ubuntu"
printf 'ID=pop\nID_LIKE="ubuntu debian"\n' > "$tmp/pop"
printf 'ID=rhel\nID_LIKE="fedora"\n' > "$tmp/rhel"
printf 'ID="../etc"\n' > "$tmp/evil"

[[ "$(run "$tmp/ubuntu")" == ubuntu ]] || { echo "ubuntu not selected"; exit 1; }
[[ "$(run "$tmp/pop")" == ubuntu ]] || { echo "ID_LIKE fallback failed"; exit 1; }
[[ "$(run "$tmp/rhel")" == "" ]] || { echo "unknown distro should fail"; exit 1; }
[[ "$(run "$tmp/evil")" == "" ]] || { echo "path-like ID should fail"; exit 1; }
[[ "$(run "$tmp/rhel" ubuntu)" == ubuntu ]] || { echo "override failed"; exit 1; }
echo "backend selection ok"
