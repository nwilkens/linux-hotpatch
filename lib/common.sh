# shellcheck shell=bash
# Shared helpers for the hotpatch tool.

HOTPATCH_WORKDIR="${HOTPATCH_WORKDIR:-/var/lib/linux-hotpatch}"

log()  { printf '[hotpatch] %s\n' "$*" >&2; }
die()  { printf '[hotpatch] error: %s\n' "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "must run as root"; }

need_cmd() {
	local c
	for c in "$@"; do
		command -v "$c" >/dev/null 2>&1 || die "missing command: $c (run: hotpatch deps)"
	done
}

# sha256_check <file> <expected-hex>
sha256_check() {
	local actual
	actual="$(sha256sum "$1" | awk '{print $1}')"
	[[ "$actual" == "$2" ]] || die "checksum mismatch for $1: got $actual want $2"
}

# fetch <url> <dest>: download to a temp file, then move into place.
fetch() {
	local url="$1" dest="$2"
	[[ -s "$dest" ]] && { log "cached: $dest"; return 0; }
	mkdir -p "$(dirname "$dest")"
	local shown
	shown="$(sed -E 's#//[^/@]*@#//#' <<<"$url")"
	log "fetching $shown"
	curl -fL -sS --retry 3 --connect-timeout 20 --proto '=https' --tlsv1.2 -A 'linux-hotpatch' -o "$dest.part" "$url" \
		|| { log "download failed: $shown"; return 1; }
	mv "$dest.part" "$dest"
}

running_kernel() { uname -r; }
