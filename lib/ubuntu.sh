# shellcheck shell=bash
# Ubuntu specifics: locate the exact source and debug kernel for the running
# kernel on Launchpad, which keeps packages the archive pool has dropped.

LP_SRC="https://launchpad.net/ubuntu/+archive/primary/+sourcefiles"
LP_BIN="https://launchpad.net/ubuntu/+archive/primary/+files"

# Sets KVER, SRC_PKG, PKG_VER, FLAVOUR, ABI for the running kernel.
ubuntu_detect() {
	KVER="$(running_kernel)"
	dpkg-query -W "linux-image-$KVER" >/dev/null 2>&1 \
		|| die "linux-image-$KVER is not an installed package"
	SRC_PKG="$(dpkg-query -W -f='${Source}' "linux-image-$KVER" | sed 's/-signed//; s/ .*//')"
	PKG_VER="$(dpkg-query -W -f='${Version}' "linux-image-$KVER")"
	FLAVOUR="${KVER##*-}"
	ABI="${KVER#*-}"; ABI="${ABI%-*}"
	UPSTREAM_VER="${PKG_VER%%-*}"
	SRC_DIR="$HOTPATCH_WORKDIR/src"
	SRC_TREE="$SRC_DIR/$SRC_PKG-$UPSTREAM_VER"
	VMLINUX="$HOTPATCH_WORKDIR/dbg/usr/lib/debug/boot/vmlinux-$KVER"
	CONFIG="/boot/config-$KVER"
	[[ -r "$CONFIG" ]] || die "missing $CONFIG"
	log "kernel $KVER  source $SRC_PKG $PKG_VER  flavour $FLAVOUR abi $ABI"
}

# Download dsc + orig + diff, check each file against the dsc's sha256 list,
# then unpack. The dsc signature itself is not verified: uploader keys are not
# in any keyring shipped with Ubuntu, so trust rests on TLS to Launchpad.
ubuntu_fetch_source() {
	need_cmd dpkg-source curl patch
	local dsc="${SRC_PKG}_${PKG_VER}.dsc"
	local base="$LP_SRC/$SRC_PKG/$PKG_VER"
	mkdir -p "$SRC_DIR"
	fetch "$base/$dsc" "$SRC_DIR/$dsc"
	local sum f
	while read -r sum _ f; do
		[[ -n "$f" ]] || continue
		fetch "$base/$f" "$SRC_DIR/$f"
		sha256_check "$SRC_DIR/$f" "$sum"
	done < <(sed -n '/^Checksums-Sha256:/,/^[A-Z]/{/^ /p}' "$SRC_DIR/$dsc")

	if [[ -e "$SRC_TREE/Makefile" ]]; then
		log "source tree present: $SRC_TREE"
	else
		log "unpacking source into $SRC_TREE"
		(cd "$SRC_DIR" && dpkg-source -x "$dsc" "$SRC_TREE" >/dev/null) \
			|| die "dpkg-source failed"
	fi
	ubuntu_prep_tree
}

# Make a plain upstream-style tree produce the Ubuntu release string.
ubuntu_prep_tree() {
	echo "-$ABI-$FLAVOUR" > "$SRC_TREE/localversion"
	sed -i 's/^SUBLEVEL.*/SUBLEVEL = 0/' "$SRC_TREE/Makefile"
	rm -rf "$SRC_TREE/.git"
	local rel
	rel="$(make -s -C "$SRC_TREE" kernelversion)$(cat "$SRC_TREE/localversion")"
	[[ "$rel" == "$KVER" ]] || die "tree would build $rel, running kernel is $KVER"
}

# The -dbgsym ddeb is ~2GB; extract only vmlinux from it.
ubuntu_fetch_vmlinux() {
	need_cmd dpkg-deb tar readelf
	local arch ddeb
	arch="$(dpkg --print-architecture)"
	ddeb="linux-image-unsigned-${KVER}-dbgsym_${PKG_VER}_${arch}.ddeb"
	local dbg="$HOTPATCH_WORKDIR/dbg"
	if [[ ! -s "$VMLINUX" ]]; then
		fetch "$LP_BIN/$ddeb" "$dbg/$ddeb"
		log "extracting vmlinux from $ddeb"
		mkdir -p "$dbg"
		dpkg-deb --fsys-tarfile "$dbg/$ddeb" \
			| tar -x -C "$dbg" "./usr/lib/debug/boot/vmlinux-$KVER" \
			|| die "could not extract vmlinux"
		rm -f "$dbg/$ddeb"
	fi
	ubuntu_verify_vmlinux
}

# The running kernel exposes its ELF notes; the GNU build-id in there must
# equal the one in the debug vmlinux or the symbols are for another build.
ubuntu_verify_vmlinux() {
	local want have
	want="$(python3 -I - <<'PY'
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
)"
	have="$(readelf -n "$VMLINUX" | awk '/Build ID/ {print $3}')"
	[[ -n "$want" && "$want" == "$have" ]] \
		|| die "vmlinux build-id $have does not match running kernel $want"
	log "vmlinux build-id verified: $have"
}
