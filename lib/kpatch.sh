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

# kpatch_build <name> [--cumulative] [kpatch-build args] -- <patch>...
# Modules are built non-replace by default so each fix loads and unloads on
# its own. --cumulative builds a replace module that supersedes every loaded
# livepatch, for a combined module that carries all of them.
kpatch_build() {
	local name="$1" replace=0 p; shift
	local -a flags=() patches=()
	while [[ $# -gt 0 && "$1" != "--" ]]; do
		if [[ "$1" == "--cumulative" ]]; then
			replace=1
		else
			flags+=("$1")
		fi
		shift
	done
	shift || true
	[[ $replace -eq 1 ]] || flags+=(-R)
	for p in "$@"; do
		p="$(readlink -f "$p")"
		[[ -r "$p" ]] || die "patch not readable: $p"
		patches+=("$p")
	done
	[[ ${#patches[@]} -gt 0 ]] || die "no patches given"
	( cd "$SRC_TREE" && cat "${patches[@]}" | patch -p1 -N --dry-run -s ) \
		|| die "patches do not apply cleanly together to $SRC_TREE"
	kpatch_compiler_report
	backend_build_env
	local out="$HOTPATCH_WORKDIR/out/$name"
	mkdir -p "$out"
	export CACHEDIR="$HOTPATCH_WORKDIR/kpatch-cache"
	log "building livepatch $name (on failure see $CACHEDIR/build.log)"
	"$KPATCH_DIR/kpatch-build/kpatch-build" \
		--sourcedir "$SRC_TREE" \
		--config "$CONFIG" \
		--vmlinux "$VMLINUX" \
		--jobs "$(nproc)" \
		--name "$name" \
		--output "$out" \
		"${flags[@]}" "${patches[@]}" || die "kpatch-build failed, see $CACHEDIR/build.log"
	log "built: $out/$name.ko"
	{
		echo "replace=$replace"
		for p in "${patches[@]}"; do
			printf 'patch=%s %s\n' "$(basename "$p")" \
				"$(grep -m1 '^Subject: ' "$p" | sed -E 's/^Subject: (\[PATCH[^]]*\] *)?//')"
		done
	} > "$out/$name.manifest"
	modinfo "$out/$name.ko" | grep -E '^(vermagic|livepatch|name):'
	lp_check_versions "$out/$name.ko"
	kernel_build_id > "$out/$name.buildid"
	log "patched functions:"
	readelf -p .kpatch.strings "$out/$name.ko" | awk -F'] *' 'NR>2 && NF>1 {print $2}' | paste - - | awk '{print "  " $1 ": " $2}'
}
