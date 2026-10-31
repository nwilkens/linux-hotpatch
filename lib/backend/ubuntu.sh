# shellcheck shell=bash
# Ubuntu backend: locate the exact source and debug kernel for the running
# kernel on Launchpad, which keeps packages the archive pool has dropped.
# A backend defines backend_detect, backend_fetch_source,
# backend_fetch_vmlinux and backend_build_env, and sets KVER, SRC_TREE,
# VMLINUX and CONFIG.

# shellcheck source=lib/backend/apt-archive.sh
source "$HOTPATCH_HOME/lib/backend/apt-archive.sh"

LP_SRC="https://launchpad.net/ubuntu/+archive/primary/+sourcefiles"
LP_BIN="https://launchpad.net/ubuntu/+archive/primary/+files"

# Where to get the source files. Launchpad redirects to launchpadlibrarian.net,
# which some networks cannot reach; HOTPATCH_POOL names an archive root with a
# pool/ layout to use instead, such as
# https://snapshot.ubuntu.com/ubuntu/20250601T000000Z for a superseded package.
source_base() {
	if [[ -n "${HOTPATCH_POOL:-}" ]]; then
		local letter="${SRC_PKG:0:1}"
		[[ "$SRC_PKG" == lib* ]] && letter="${SRC_PKG:0:4}"
		printf '%s/pool/main/%s/%s' "${HOTPATCH_POOL%/}" "$letter" "$SRC_PKG"
	else
		printf '%s/%s/%s' "$LP_SRC" "$SRC_PKG" "$PKG_VER"
	fi
}

# Sets KVER, SRC_PKG, PKG_VER, FLAVOUR, ABI for the running kernel.
backend_detect() {
	KVER="$(running_kernel)"
	dpkg-query -W "linux-image-$KVER" >/dev/null 2>&1 \
		|| die "linux-image-$KVER is not an installed package"
	SRC_PKG="$(dpkg-query -W -f='${Source}' "linux-image-$KVER" | sed 's/-signed//; s/ .*//')"
	PKG_VER="$(dpkg-query -W -f='${Version}' "linux-image-$KVER")"
	FLAVOUR="${KVER##*-}"
	ABI="${KVER#*-}"; ABI="${ABI%-*}"
	SRC_DIR="$HOTPATCH_WORKDIR/src"
	SRC_TREE="$SRC_DIR/$SRC_PKG-$PKG_VER"
	VMLINUX="$HOTPATCH_WORKDIR/dbg/usr/lib/debug/boot/vmlinux-$KVER"
	CONFIG="/boot/config-$KVER"
	[[ -r "$CONFIG" ]] || die "missing $CONFIG"
	log "kernel $KVER  source $SRC_PKG $PKG_VER  flavour $FLAVOUR abi $ABI"
}

# Download dsc + orig + diff, check each file against the dsc's sha256 list,
# then unpack. From Launchpad the dsc is trusted on TLS alone, since uploader
# keys are in no shipped keyring; from a pool mirror it is checked against the
# archive-signed Sources index.
backend_fetch_source() {
	need_cmd dpkg-source curl patch
	local dsc="${SRC_PKG}_${PKG_VER}.dsc"
	local base
	base="$(source_base)"
	mkdir -p "$SRC_DIR"
	fetch "$base/$dsc" "$SRC_DIR/$dsc" || die "could not fetch $dsc"
	if [[ -n "${HOTPATCH_POOL:-}" ]]; then
		( archive_verify_dsc "$SRC_DIR/$dsc" ) \
			|| { rm -f "$SRC_DIR/$dsc"; die "dsc verification failed"; }
	fi
	local sum f
	while read -r sum _ f; do
		[[ -n "$f" ]] || continue
		[[ "$f" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]*$ ]] || die "unexpected file name in dsc: $f"
		fetch "$base/$f" "$SRC_DIR/$f" || die "could not fetch $f"
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
backend_fetch_vmlinux() {
	need_cmd dpkg-deb tar readelf
	local arch ddeb
	arch="$(dpkg --print-architecture)"
	ddeb="linux-image-unsigned-${KVER}-dbgsym_${PKG_VER}_${arch}.ddeb"
	local dbg="$HOTPATCH_WORKDIR/dbg"
	if [[ ! -s "$VMLINUX" ]]; then
		fetch "$LP_BIN/$ddeb" "$dbg/$ddeb" || die "could not fetch $ddeb; place it under $dbg/ by hand"
		log "extracting vmlinux from $ddeb"
		mkdir -p "$dbg"
		dpkg-deb --fsys-tarfile "$dbg/$ddeb" \
			| tar -x -C "$dbg" "./usr/lib/debug/boot/vmlinux-$KVER" \
			|| die "could not extract vmlinux"
		rm -f "$dbg/$ddeb"
	fi
	verify_vmlinux
}

# Ubuntu's debian/rules.d/0-common-vars.mk passes these on the make command
# line rather than through .config, so /boot/config-* does not record them.
# Without CONFIG_DEBUG_SECTION_MISMATCH the compiler inlines once-called
# functions and the static symbols no longer match the shipped vmlinux.
backend_build_env() {
	export CONFIG_DEBUG_SECTION_MISMATCH=y
	export CFLAGS_MODULE="-DPKG_ABI=$ABI"
}
