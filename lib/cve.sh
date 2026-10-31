# shellcheck shell=bash
# Turn a CVE id into a patch that applies to the prepared source tree.

CVE_RECORDS="https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published"
STABLE_PATCH="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id="
CVE_DIR="$HOTPATCH_WORKDIR/cve"

is_cve_id() { [[ "$1" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]]; }

# cve_module_name CVE-2026-98432 -> cve_2026_98432
cve_module_name() { local n="${1,,}"; printf '%s\n' "${n//-/_}"; }

cve_patch_applies() { ( cd "$SRC_TREE" && patch -p1 -N --dry-run -s < "$1" ) >/dev/null 2>&1; }
cve_patch_reverts() { ( cd "$SRC_TREE" && patch -p1 -R --dry-run -s < "$1" ) >/dev/null 2>&1; }

# cve_patch_path <id>: the curated patch if the repo ships one that applies
# to this tree, else the fetched one.
cve_patch_path() {
	local id="$1" curated
	curated="$HOTPATCH_HOME/patches/$id.patch"
	if [[ -r "$curated" ]] && cve_patch_applies "$curated"; then
		printf '%s\n' "$curated"
	else
		printf '%s\n' "$CVE_DIR/$id.patch"
	fi
}

# cve_fetch_patch <id>: download the CNA record, try each fixing commit
# against the source tree starting with the nearest stable branch, and keep
# the first one that applies.
cve_fetch_patch() {
	local id="$1" json candidate commit branch subject dest
	is_cve_id "$id" || die "not a CVE id: $id"
	[[ -d "$SRC_TREE" ]] || die "no source tree at $SRC_TREE; run 'hotpatch prepare'"
	dest="$(cve_patch_path "$id")"
	if [[ -r "$dest" ]] && cve_patch_applies "$dest"; then
		log "using $dest"
		return 0
	fi
	if [[ -r "$dest" ]] && cve_patch_reverts "$dest"; then
		die "$id: $dest is already present in $SRC_TREE"
	fi
	[[ -r "$HOTPATCH_HOME/patches/$id.patch" ]] \
		&& log "$id: the curated patch does not apply to this tree; resolving from the CNA record instead"
	rm -f "$dest"
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

VULNS_REPO="https://git.kernel.org/pub/scm/linux/security/vulns.git"
VULNS_DIR="$HOTPATCH_WORKDIR/vulns"

# Keep a sparse checkout of the kernel CNA records for this year and last.
cve_update_records() {
	need_cmd git
	local year
	year="$(date +%Y)"
	if [[ -d "$VULNS_DIR/.git" ]]; then
		git -C "$VULNS_DIR" pull -q --depth 1 || die "could not update $VULNS_DIR"
	else
		git clone -q --depth 1 --sparse "$VULNS_REPO" "$VULNS_DIR" || die "could not clone $VULNS_REPO"
	fi
	git -C "$VULNS_DIR" sparse-checkout set --no-cone "cve/published/$year" "cve/published/$((year - 1))" \
		|| die "sparse checkout failed"
}

LORE="https://lore.kernel.org/linux-cve-announce/"

# cve_announced <from> <to> <ids-file>: CVE ids announced on linux-cve-announce
# in the date range, from lore's search, 200 per page.
cve_announced() {
	local from="${1//-/}" to="${2//-/}" ids="$3" page offset=0 n
	: > "$ids"
	while :; do
		page="$CVE_DIR/lore/$from-$to-$offset.atom"
		rm -f "$page"
		fetch "$LORE?q=d:$from..$to&x=A&o=$offset" "$page" || die "lore search failed"
		n="$(grep -c '<entry>' "$page" || true)"
		grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$page" >> "$ids" || true
		[[ "$n" -ge 200 ]] || break
		offset=$((offset + 200))
	done
	sort -u "$ids" -o "$ids"
	log "$(wc -l < "$ids") CVEs announced between $1 and $2"
}

# cve_catalog <from> [<to>]: every CVE announced in the range that affects
# this kernel, resolved against the source tree and summarised one per line.
cve_catalog() {
	local from="$1" to="${2:-$(date +%F)}" out ids id commit title status detail
	[[ "$from" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && "$to" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "dates are YYYY-MM-DD"
	cve_update_records
	mkdir -p "$CVE_DIR"
	ids="$CVE_DIR/announced-$from-$to.txt"
	cve_announced "$from" "$to" "$ids"
	out="$CVE_DIR/catalog-$from-$to.tsv"
	printf 'cve\tstatus\tdetail\ttitle\n' > "$out"
	while IFS=$'\t' read -r id commit title; do
		detail=""
		if [[ "$commit" == "-" ]]; then
			status="no-record"
		elif ( cve_fetch_patch "$id" ) > "$CVE_DIR/$id.log" 2>&1; then
			detail="$(python3 -I "$HOTPATCH_HOME/scripts/inspect-patch.py" --brief \
				--src "$SRC_TREE" --config "$CONFIG" "$(cve_patch_path "$id")" 2>&1 | tail -1)"
			status="applies"
			[[ "$detail" == *"review=0"* ]] || status="review"
		elif grep -q "already present" "$CVE_DIR/$id.log"; then
			status="present"
		else
			status="no-fix"
		fi
		printf '%s\t%s\t%s\t%s\n' "$id" "$status" "$detail" "$title" | tee -a "$out"
	done < <(python3 -I "$HOTPATCH_HOME/scripts/cve-catalog.py" "$VULNS_DIR" "$KVER" "$ids")
	log "catalog written to $out"
}
