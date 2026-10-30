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

lp_status() {
	local p
	[[ -d $LP_SYS ]] || die "no livepatch support in this kernel"
	for p in "$LP_SYS"/*/; do
		[[ -d "$p" ]] || { log "no livepatches loaded"; return 0; }
		p="${p%/}"
		printf '%s enabled=%s transition=%s\n' "${p##*/}" "$(cat "$p/enabled")" "$(cat "$p/transition")"
		find "$p" -mindepth 2 -maxdepth 2 -type d -printf '  %P\n'
	done
}

lp_load() {
	local ko="$1" name
	[[ -r "$ko" ]] || die "module not readable: $ko"
	name="$(modinfo -F name "$ko")"
	[[ "$(modinfo -F livepatch "$ko")" == "Y" ]] || die "$ko is not a livepatch module"
	[[ "$(modinfo -F vermagic "$ko" | awk '{print $1}')" == "$(running_kernel)" ]] \
		|| die "vermagic does not match running kernel"
	[[ -d "$LP_SYS/$name" ]] && die "$name is already loaded"
	log "loading $name"
	insmod "$ko" || die "insmod failed: $(dmesg | tail -5)"
	lp_wait_transition "$name" || die "transition did not complete; check 'hotpatch status' and dmesg"
	log "$name enabled=$(cat "$LP_SYS/$name/enabled") transition complete"
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
