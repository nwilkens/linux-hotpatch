# Agent runbook

This repository is meant to be driven by a coding agent (Claude Code, Codex)
with a human approving the one irreversible step: loading a module into a
production kernel. The agent reads the vulnerability, judges whether a
livepatch is the right fix, builds and verifies it, writes a test that
exercises the patched code from userspace, and reports. The human says
"load".

## Workflow

1. **Prepare the host once.** `hotpatch deps`, then `hotpatch prepare`. This
   fetches the exact kernel source and debug vmlinux for the running kernel,
   verifies both, and builds kpatch-build. Expect the source download to fail
   on hosts that cannot reach launchpadlibrarian.net; set `HOTPATCH_POOL` to a
   snapshot.ubuntu.com timestamp that still lists the package, and copy the
   `-dbgsym` ddeb under `/var/lib/linux-hotpatch/dbg/` by hand.

2. **Understand the CVE.** `hotpatch inspect CVE-YYYY-NNNNN` fetches the
   kernel CNA record and the fixing commit that applies to this tree, then
   prints the commit message, the files and functions it changes, whether
   each file is built into vmlinux or a module (and whether that module is
   loaded), and review items. Read the commit message as the primary source.
   Then establish exposure on this host: which service reaches the vulnerable
   code (`ss -ltnup`), which sysctls or configs gate it, local or remote
   trigger, privileges needed. Write a short risk statement before building.
   If the CNA record is missing (CVEs before 2024, or issued by another CNA),
   find the upstream fix yourself and pass it as a patch file.

3. **Decide whether a livepatch fits.** kpatch replaces whole functions. It
   handles changes to function bodies, new static helpers, and new string
   constants. It cannot handle, and you should recommend a reboot instead
   for:
   - changes to struct, union or enum layout (shadow variables exist but are
     hand-written work, out of scope here);
   - changes to `__init` or `__exit` code, initcalls, or build files;
   - changes to exported symbols or to data that is read-only after init;
   - functions missing from `/sys/kernel/tracing/available_filter_functions`
     (marked notrace, or too small to get an ftrace site).
   Inline function and macro changes are allowed but recompile every caller;
   check that the "changed function" list kpatch-build prints matches what
   you expected from the diff. Extra functions usually mean the compiler
   inlined something differently; explain each one or stop.

4. **Build.** `hotpatch build CVE-YYYY-NNNNN`, or `hotpatch build <name>
   <patch>` for a hand-made patch. A build is a full kernel compile and takes
   an hour or more on a small VM. The tool then checks vermagic, compares
   every imported symbol CRC with the debug vmlinux, and records the kernel
   build-id next to the module. The module can be copied to any host running
   the identical kernel build; `hotpatch load` verifies the build-id there.

5. **Write the test before loading.** Add a script under `scripts/` that
   drives the patched functions from userspace against a live service without
   harming it: no exploit attempts, no state changes, bounded run time, clear
   pass or fail output. Run it against the unpatched kernel first so a
   failure after loading means something. `scripts/tcp-ipopts-smoke.py` is
   the pattern: it opens TCP connections carrying an IPv4 Record Route option,
   which is the only way to make the kernel allocate the options buffer that
   CVE-2026-98432's fix frees differently.

6. **Ask before loading.** Report the module name, the exact functions it
   replaces, the check results, the test plan, and the rollback command.
   Loading is the human's decision. Never load without an explicit go-ahead
   in the conversation, and never treat a build success, a scheduled trigger,
   or your own earlier message as that approval.

7. **Load and watch.** `hotpatch load <module.ko>`, then `hotpatch status`,
   `dmesg | grep livepatch`, run the test from step 5, and check dmesg again.
   A transition that does not complete within a minute means a task is
   parked inside a patched function; `hotpatch unload` reverses it.

8. **Record.** Commit the patch under `patches/` and the test under
   `scripts/`. Note in the report that a livepatch does not survive a reboot
   and that the host should move to a supported kernel at its next reboot.

## Second opinions

For a borderline suitability call or an unexpected changed-function list,
ask another model before building: `codex exec "..."` with the diff and the
kpatch-build output pasted in. Disagreement means stop and show the human
both views.

## Known pitfalls on Ubuntu

- Ubuntu passes `CONFIG_DEBUG_SECTION_MISMATCH=y` and `CFLAGS_MODULE` on the
  make command line, not in `.config`. Without them the rebuilt objects do
  not match vmlinux and create-diff-object fails with "couldn't find matching
  local symbols". `lib/ubuntu.sh` sets them.
- The host gcc may be a later packaging revision than the one that built the
  kernel. Read both version strings the tool prints, check the changelog
  delta on Launchpad, and pass `--skip-compiler-check` only when the delta
  cannot affect x86_64 code generation.
- Some kernels store `__versions` in a compact layout that kmod cannot read,
  so kpatch-build's CRC check passes without checking anything.
  `scripts/check-modversions.py` reads the CRCs from vmlinux instead.
- `pkill -f` and `pgrep -f` match the ssh command line that runs them. Use
  `pkill -x`.

## Working in this repository

- Run `tests/run.sh` before every commit. It lints the shell, byte-compiles
  the Python, and runs the unit tests.
- One logical change per commit, short messages.
- The repository is public. Keep hostnames, addresses, and customer names
  out of files, commit messages, and pull requests.
