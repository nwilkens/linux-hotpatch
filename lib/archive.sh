# shellcheck shell=bash
# Verify a dsc fetched from a pool mirror through the archive's signed chain:
# InRelease (Ubuntu archive key) -> Sources.gz sha256 -> dsc sha256.

UBUNTU_KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg

# archive_verify_dsc <dsc-path>; uses HOTPATCH_POOL, SRC_PKG, PKG_VER.
archive_verify_dsc() {
	need_cmd gpgv zcat awk
	[[ -r "$UBUNTU_KEYRING" ]] || die "missing $UBUNTU_KEYRING (install ubuntu-keyring)"
	local dsc="$1" codename suite want
	# shellcheck source=/dev/null
	codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
	for suite in "$codename-updates" "$codename-security" "$codename-proposed" "$codename"; do
		want="$(archive_dsc_sha256 "$suite" "${dsc##*/}")" || continue
		sha256_check "$dsc" "$want"
		log "dsc verified via signed $suite index"
		return 0
	done
	die "${dsc##*/} not found in any signed Sources index under $HOTPATCH_POOL"
}

# Print the sha256 the signed Sources index of <suite> records for <dsc-name>.
archive_dsc_sha256() {
	local suite="$1" name="$2"
	local dir="$HOTPATCH_WORKDIR/index/$suite"
	local inrelease="$dir/InRelease" body="$dir/Release.body" sources="$dir/Sources.gz"
	mkdir -p "$dir"
	fetch "${HOTPATCH_POOL%/}/dists/$suite/InRelease" "$inrelease" || return 1
	gpgv --quiet --keyring "$UBUNTU_KEYRING" --output "$body" "$inrelease" 2>/dev/null \
		|| die "InRelease for $suite is not signed by the Ubuntu archive key"
	local sum
	sum="$(awk '/^SHA256:/ {s=1; next} /^[A-Z]/ {s=0} s && $3=="main/source/Sources.gz" && length($1)==64 {print $1}' "$body")"
	[[ -n "$sum" ]] || return 1
	fetch "${HOTPATCH_POOL%/}/dists/$suite/main/source/Sources.gz" "$sources" || return 1
	sha256_check "$sources" "$sum"
	zcat "$sources" | awk -v p="$SRC_PKG" -v v="$PKG_VER" -v f="$name" '
		BEGIN { RS=""; FS="\n" }
		{
			ok = 0
			for (i = 1; i <= NF; i++) if ($i == "Package: " p || $i == "Version: " v) ok++
			if (ok != 2) next
			for (i = 1; i <= NF; i++) {
				n = split($i, a, " ")
				if (n == 3 && a[3] == f && length(a[1]) == 64) { print a[1]; exit }
			}
		}' | grep -E '^[0-9a-f]{64}$'
}
