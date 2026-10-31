# linux-hotpatch

Builds kernel livepatch modules for the running Linux kernel from a CVE id
with [kpatch](https://github.com/dynup/kpatch) and loads them without a
reboot. Distribution specifics sit in one backend file under `lib/backend/`;
Ubuntu is the first backend.

On Ubuntu, source and debug symbols come from Launchpad, which still serves
packages the archive pool has dropped, so end-of-life HWE kernels can be
patched. The debug vmlinux is checked against the running kernel's GNU
build-id before use, and each built module's symbol versions are compared
with it before loading.

## Use

    scripts/deploy.sh root@host ~/.ssh/key   # copy to /root/linux-hotpatch
    ./hotpatch deps
    ./hotpatch prepare
    ./hotpatch inspect CVE-2026-98432
    ./hotpatch build CVE-2026-98432
    ./hotpatch load /var/lib/linux-hotpatch/out/cve_2026_98432/cve_2026_98432.ko
    ./hotpatch status
    ./hotpatch unload cve_2026_98432

Each CVE builds into its own module by default, and modules stack: load the
ones you want, unload any one of them on its own. `load` refuses a module
that replaces a function another loaded livepatch already patches, because
the new version would not carry the older fix; build one module from both
patches in that case:

    ./hotpatch build net_fixes CVE-2026-98432 CVE-2026-99211

`--cumulative` instead builds a module that supersedes every loaded livepatch
when loaded with `--replace`, for sites that prefer one module carrying all
fixes. Each build writes a `.manifest` beside the module listing what it
carries, and `status` shows it for loaded modules.

`patches/<series>/` holds pre-resolved patches for a kernel series with an
`INDEX.tsv` (status, changed functions, object, title) produced by
`hotpatch catalog <from> [<to>]` and `hotpatch export <catalog.tsv> patches`.
`build` uses a shipped patch when it applies and otherwise resolves the CVE
from the kernel CNA record.

`inspect` and `build` take a CVE id. The tool reads the kernel CNA record
from kernel.org, downloads each fixing commit starting with the stable branch
nearest the running kernel, and keeps the first one that applies to the
source tree. A patch the repository ships under `patches/` wins over a
download. `build <name> <patch>` takes any patch file.

`inspect` prints the commit message, the changed files and functions, whether
each file is built into vmlinux or a module, and review items such as type or
init-code changes that a livepatch cannot carry. `build` verifies vermagic,
compares every imported symbol CRC with the debug vmlinux, and writes the
kernel build-id next to the module; `load` checks either before insmod, so the
module can be copied to other hosts running the same kernel build.

State lives under `/var/lib/linux-hotpatch` (override with `HOTPATCH_WORKDIR`).
Set `HOTPATCH_POOL` to an archive root with a `pool/` layout, for example
`https://snapshot.ubuntu.com/ubuntu/20250601T000000Z`, when the host cannot
reach launchpadlibrarian.net. The debug kernel can be pre-seeded by placing the
`-dbgsym` ddeb under `/var/lib/linux-hotpatch/dbg/`.
Extra arguments after the CVE id or patch path go to kpatch-build, for example
`--skip-compiler-check` when the local gcc is a later packaging revision of the
one that built the kernel.

docs/build-service.md is a proposal for turning this into an open build
service for any kernel. AGENTS.md is the runbook for driving this with a
coding agent. Run
`tests/run.sh` before committing.

## Patches

- `patches/CVE-2026-98432.patch`: upstream e3f33b0a1d89, "ipv4: free inet_opt
  and ireq_opt after an RCU grace period".

## Checking a loaded patch

`hotpatch status` lists each livepatch with its enabled and transition state
and the functions it replaces. `scripts/tcp-ipopts-smoke.py HOST 22` opens
connections carrying an IPv4 Record Route option, the path that allocates the
options buffer the CVE-2026-98432 fix frees under RCU.
