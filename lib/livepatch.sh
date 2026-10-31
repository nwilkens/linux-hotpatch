# shellcheck shell=bash
# Load, inspect and remove livepatch modules through sysfs.

LP_SYS=/sys/kernel/livepatch

lp_wait_transition() {
	local name="$1"
	for _ in $(seq 1 60); do
		[[ "$(cat "$LP_SYS/$name/transition" 2>/dev/null)" == "0" ]] && return 0
		sleep 1
	done
	return 1
}

# kmod cannot read the compact __versions layout some kernels use, so
# kpatch-build's own check passes vacuously; compare against vmlinux here.
lp_check_versions() {
	local ko="$1"
	[[ -r "$VMLINUX" ]] || die "debug vmlinux not found at $VMLINUX; run 'hotpatch prepare'"
	python3 -I "$HOTPATCH_HOME/scripts/check-modversions.py" "$ko" "$VMLINUX" \
		|| die "symbol versions in $ko do not match $VMLINUX"
}

lp_status() {
	local p
	[[ -d $LP_SYS ]] || die "no livepatch support in this kernel"
	for p in "$LP_SYS"/*/; do
		[[ -d "$p" ]] || { log "no livepatches loaded"; return 0; }
		p="${p%/}"
		printf '%s enabled=%s transition=%s replace=%s\n' "${p##*/}" "$(cat "$p/enabled")" "$(cat "$p/transition")" "$(cat "$p/replace" 2>/dev/null || echo '?')"
		find "$p" -mindepth 2 -maxdepth 2 -type d -printf '  %P\n'
	done
}

# Names of loaded livepatches other than $1.
lp_others() {
	local p
	for p in "$LP_SYS"/*/; do
		[[ -d "$p" ]] || continue
		p="${p%/}"; p="${p##*/}"
		[[ "$p" == "$1" ]] || printf '%s\n' "$p"
	done
}

lp_load() {
	local ko="$1" replace_ok="${2:-}" name others replace=1
	[[ -r "$ko" ]] || die "module not readable: $ko"
	[[ -z "$replace_ok" || "$replace_ok" == "--replace" ]] || die "unknown option $replace_ok"
	name="$(modinfo -F name "$ko")"
	[[ -r "${ko%.ko}.manifest" ]] && replace="$(sed -n 's/^replace=//p' "${ko%.ko}.manifest")"
	others="$(lp_others "$name")"
	if [[ -n "$others" && "$replace" != 0 && "$replace_ok" != "--replace" ]]; then
		die "loading $name would supersede: $(tr '\n' ' ' <<<"$others")" \
			"(kpatch modules replace loaded livepatches). Build one cumulative" \
			"module carrying every fix and pass --replace."
	fi
	[[ "$(modinfo -F livepatch "$ko")" == "Y" ]] || die "$ko is not a livepatch module"
	[[ "$(modinfo -F vermagic "$ko" | awk '{print $1}')" == "$(running_kernel)" ]] \
		|| die "vermagic does not match running kernel"
	local checked=0
	if [[ -r "${ko%.ko}.buildid" ]]; then
		[[ "$(cat "${ko%.ko}.buildid")" == "$(kernel_build_id)" ]] \
			|| die "$ko was built for a different kernel build (build-id mismatch)"
		log "build-id matches the running kernel"
		checked=1
	fi
	if [[ -r "${VMLINUX:-}" ]]; then
		lp_check_versions "$ko"
		checked=1
	fi
	[[ $checked -eq 1 ]] || die "cannot verify $ko: no debug vmlinux and no ${ko%.ko}.buildid"
	[[ -d "$LP_SYS/$name" ]] && die "$name is already loaded"
	log "loading $name"
	insmod "$ko" || die "insmod failed: $(dmesg | tail -5)"
	lp_wait_transition "$name" || die "transition did not complete; check 'hotpatch status' and dmesg"
	log "$name enabled=$(cat "$LP_SYS/$name/enabled") transition complete"
	local o
	for o in $others; do
		if [[ ! -d "$LP_SYS/$o" ]]; then
			rmmod "$o" 2>/dev/null && log "removed superseded $o"
		fi
	done
	dmesg | grep -i "livepatch" | tail -5
}

lp_unload() {
	local name="$1"
	[[ -d "$LP_SYS/$name" ]] || die "$name is not loaded"
	echo 0 > "$LP_SYS/$name/enabled"
	lp_wait_transition "$name" || die "disable transition did not complete"
	rmmod "$name" || die "rmmod failed"
	log "$name removed"
}
