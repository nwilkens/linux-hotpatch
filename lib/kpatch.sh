# shellcheck shell=bash
# Build kpatch-build from a pinned release and drive it.

KPATCH_REPO="https://github.com/dynup/kpatch.git"
KPATCH_TAG="v0.9.11"
KPATCH_COMMIT="bea635fbbeb11c5f0f5c0d4ffce34c2e9d2e8a6a"
KPATCH_DIR="$HOTPATCH_WORKDIR/kpatch"

kpatch_install() {
	need_cmd git make gcc
	if [[ ! -d "$KPATCH_DIR/.git" ]]; then
		git clone -q --depth 1 --branch "$KPATCH_TAG" "$KPATCH_REPO" "$KPATCH_DIR" \
			|| die "git clone failed"
	fi
	local got
	got="$(git -C "$KPATCH_DIR" rev-parse HEAD)"
	[[ "$got" == "$KPATCH_COMMIT" ]] || die "kpatch checkout is $got, expected $KPATCH_COMMIT"
	[[ -x "$KPATCH_DIR/kpatch-build/create-diff-object" ]] \
		|| make -s -C "$KPATCH_DIR/kpatch-build" || die "kpatch-build compile failed"
	log "kpatch-build $KPATCH_TAG ready"
}

# Report the compiler recorded in vmlinux next to the local one.
kpatch_compiler_report() {
	local kgcc lgcc
	kgcc="$(readelf -p .comment "$VMLINUX" | awk -F'] *' '/GCC/ {print $2; exit}')"
	lgcc="$(gcc --version | head -1)"
	log "kernel built with: $kgcc"
	log "local compiler:    $lgcc"
}

# kpatch_build <name> <patch> [extra kpatch-build args]
kpatch_build() {
	local name="$1" patch="$2"; shift 2
	[[ -r "$patch" ]] || die "patch not readable: $patch"
	( cd "$SRC_TREE" && patch -p1 -N --dry-run -s < "$patch" ) \
		|| die "patch does not apply cleanly to $SRC_TREE"
	kpatch_compiler_report
	local out="$HOTPATCH_WORKDIR/out/$name"
	mkdir -p "$out"
	export CACHEDIR="$HOTPATCH_WORKDIR/kpatch-cache"
	log "building livepatch $name (log: $CACHEDIR/build.log)"
	"$KPATCH_DIR/kpatch-build/kpatch-build" \
		--sourcedir "$SRC_TREE" \
		--config "$CONFIG" \
		--vmlinux "$VMLINUX" \
		--jobs "$(nproc)" \
		--name "$name" \
		--output "$out" \
		"$@" "$patch" || die "kpatch-build failed, see $CACHEDIR/build.log"
	log "built: $out/$name.ko"
	modinfo "$out/$name.ko" | grep -E '^(vermagic|livepatch|name):'
}
