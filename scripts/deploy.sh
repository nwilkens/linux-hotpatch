#!/usr/bin/env bash
# Copy the tool to a target host: scripts/deploy.sh root@host [ssh-key]
set -euo pipefail
target="${1:?usage: deploy.sh user@host [ssh-key]}"
key="${2:-}"
opts=(-o BatchMode=yes)
[[ -n "$key" ]] && opts+=(-i "$key")
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rsync -az --delete --exclude .git -e "ssh ${opts[*]}" "$here/" "$target:/root/linux-hotpatch/"
echo "deployed to $target:/root/linux-hotpatch"
