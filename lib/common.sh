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

# GNU build-id of the running kernel, from the ELF notes it exposes.
kernel_build_id() {
	python3 -I - <<'PY'
import struct
d = open('/sys/kernel/notes', 'rb').read()
off = 0
while off + 12 <= len(d):
    n, s, t = struct.unpack_from('<III', d, off); off += 12
    name = d[off:off + n]; off += (n + 3) & ~3
    desc = d[off:off + s]; off += (s + 3) & ~3
    if name.rstrip(b'\0') == b'GNU' and t == 3:
        print(desc.hex())
PY
}
# shellcheck disable=SC2034
HOTPATCH_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
