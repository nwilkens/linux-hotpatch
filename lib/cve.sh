# shellcheck shell=bash
# Turn a CVE id into a patch that applies to the prepared source tree.

CVE_RECORDS="https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published"
STABLE_PATCH="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id="
CVE_DIR="$HOTPATCH_WORKDIR/cve"

is_cve_id() { [[ "$1" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]]; }

# cve_module_name CVE-2026-98432 -> cve_2026_98432
cve_module_name() { local n="${1,,}"; printf '%s\n' "${n//-/_}"; }

# cve_patch_path <id>: the curated patch if the repo ships one, else the
# fetched one.
cve_patch_path() {
	local id="$1"
	if [[ -r "$HOTPATCH_HOME/patches/$id.patch" ]]; then
		printf '%s\n' "$HOTPATCH_HOME/patches/$id.patch"
	else
		printf '%s\n' "$CVE_DIR/$id.patch"
	fi
}

cve_patch_applies() { ( cd "$SRC_TREE" && patch -p1 -N --dry-run -s < "$1" ) >/dev/null 2>&1; }
cve_patch_reverts() { ( cd "$SRC_TREE" && patch -p1 -R --dry-run -s < "$1" ) >/dev/null 2>&1; }

# cve_fetch_patch <id>: download the CNA record, try each fixing commit
# against the source tree starting with the nearest stable branch, and keep
# the first one that applies.
cve_fetch_patch() {
	local id="$1" json candidate commit branch subject dest
	is_cve_id "$id" || die "not a CVE id: $id"
	[[ -d "$SRC_TREE" ]] || die "no source tree at $SRC_TREE; run 'hotpatch prepare'"
	dest="$(cve_patch_path "$id")"
	if [[ -r "$dest" ]]; then
		log "using $dest"
		cve_patch_applies "$dest" || die "$dest does not apply to $SRC_TREE"
		return 0
	fi
	json="$CVE_DIR/$id.json"
	fetch "$CVE_RECORDS/${id:4:4}/$id.json" "$json" \
		|| die "no kernel CNA record for $id (the kernel CNA covers CVEs issued since early 2024)"
	while read -r commit branch; do
		[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "unexpected commit id: $commit"
		candidate="$CVE_DIR/$id-$commit.patch"
		fetch "$STABLE_PATCH$commit" "$candidate" || die "could not fetch commit $commit"
		head -1 "$candidate" | grep -q "^From $commit " \
			|| { rm -f "$candidate"; die "$candidate is not commit $commit"; }
		if cve_patch_applies "$candidate"; then
			subject="$(grep -m1 '^Subject: ' "$candidate" | sed -E 's/^Subject: (\[PATCH[^]]*\] *)?//')"
			log "$id: using commit ${commit:0:12} from $branch"
			log "  $subject"
			cp "$candidate" "$dest"
			return 0
		fi
		if cve_patch_reverts "$candidate"; then
			die "$id: commit ${commit:0:12} ($branch) is already present in $SRC_TREE"
		fi
		log "$id: commit ${commit:0:12} ($branch) does not apply, trying the next"
	done < <(python3 -I "$HOTPATCH_HOME/scripts/cve-fix-commits.py" "$json" "$KVER")
	die "$id: no recorded fix applies to $SRC_TREE; backport one by hand and pass it to 'hotpatch build <name> <patch>'"
}
