# Livepatching an end-of-life Ubuntu kernel, with an agent doing the work

A server with 238 days of uptime, a kernel Ubuntu will never patch again, and
a new remote use-after-free in the TCP stack. No reboot window this week. This
is how we closed CVE-2026-98432 on that machine in place, how the tooling we
built along the way works for other CVEs, and what we learned about letting a
coding agent drive a kernel livepatch with a human holding the one switch that
matters.

Everything here is in [github.com/nwilkens/linux-hotpatch](https://github.com/nwilkens/linux-hotpatch).

## The problem

The host ran Ubuntu 24.04 with the hardware-enablement kernel 6.11.0-28. The
6.11 HWE series was superseded by 6.14 in 2025 and Ubuntu's security tracker
marks every CVE against it "ignored, superseded". There is no package update
coming, and Canonical Livepatch only covers supported kernels. The right
answer is to reboot into a supported kernel. The honest answer is that the
reboot was not going to happen that day, and the machine had sshd listening on
the internet.

CVE-2026-98432 is a use-after-free in IPv4 TCP connection setup. A listener
copies any IP options from a SYN into the request socket, hands them to the
child socket, and freed them with plain `kfree`. A retransmitted SYN arriving
while the child is torn down can still read the buffer while building a
SYN-ACK. Eric Dumazet's fix switches both frees to `kfree_rcu`, two one-line
changes in `inet_sock_destruct` and `tcp_v4_reqsk_destructor`. The bug dates
to Linux 4.4. The kernel CNA rates it 9.8, and a published write-up
demonstrated unauthenticated remote code execution against an MPTCP listener.
Small fix, large blast radius, perfect livepatch candidate.

## What a livepatch can and cannot do

A kernel livepatch is a module that uses ftrace to redirect calls from an old
function to a replacement compiled from the fixed source. The kernel's
consistency model switches each task over at a safe point, so a half-executed
old function finishes before its caller sees the new one. [kpatch](https://github.com/dynup/kpatch)
builds these modules by compiling the kernel twice, before and after the
patch, and extracting only the functions whose code changed.

That mechanism sets the limits. A livepatch can change function bodies. It
cannot change the layout of a struct that already lives in memory, re-run
init code, or alter exported symbols or build files. Those need a reboot or
hand-written shadow variables. Most CVE fixes in the "missing check" or "wrong
free" category fit; data structure fixes do not. Deciding which bucket a
patch falls into is the first real job.

## The tool

`hotpatch` is a small bash and Python wrapper around kpatch-build for Ubuntu
kernels. It does the parts kpatch-build does not do well on its own for a
kernel the distribution has dropped:

- finds the exact source package and debug vmlinux for the running kernel,
  from Launchpad or an Ubuntu snapshot mirror, and verifies the source
  through the archive's signed index and the vmlinux through its GNU build-id
  against `/sys/kernel/notes`;
- turns a CVE id into a patch by reading the kernel CNA's record, trying each
  fixing commit against the source tree starting with the stable branch
  nearest the running kernel, and keeping the first that applies;
- summarises the patch for review: commit message, changed functions found by
  reading the source rather than trusting hunk headers, whether each file is
  built into vmlinux or a loaded module, and flags for type, init, inline, or
  exported-symbol changes;
- builds with Ubuntu's exact make variables, then verifies vermagic, compares
  every imported symbol CRC against the debug vmlinux, and records the kernel
  build-id next to the module so it can be loaded on identical hosts;
- loads, waits for the transition, and unloads.

The sequence on a prepared host:

```
./hotpatch inspect CVE-2026-98432
./hotpatch build CVE-2026-98432
./hotpatch load /var/lib/linux-hotpatch/out/cve_2026_98432/cve_2026_98432.ko
./hotpatch status
```

## Three things that broke, and why

Anyone doing this on Ubuntu will hit the same three walls.

**The compiler check.** kpatch-build refuses to run unless the local gcc
version string matches the one recorded in vmlinux. Ours differed by one
packaging revision, `13.3.0-6ubuntu2~24.04` versus `~24.04.1`. The Launchpad
changelog for that revision is a single AArch64 SVE fix, so x86_64 code
generation is identical and `--skip-compiler-check` is justified. Read the
changelog before you pass that flag. A different major version means stop.

**Invisible make variables.** The first build died in create-diff-object with
"couldn't find matching local symbols in vmlinux symbol table". Ubuntu's
`debian/rules` passes `CONFIG_DEBUG_SECTION_MISMATCH=y` on the make command
line rather than in `.config`, which adds `-fno-inline-functions-called-once`.
Without it gcc inlines differently, the static symbol set of the rebuilt
object no longer matches the shipped kernel, and kpatch cannot line them up.
With it, every symbol matched. The tool sets this and `CFLAGS_MODULE`
automatically.

**A check that passed without checking.** kpatch-build verifies that the
module's imported symbol versions match the kernel by calling `modprobe
--dump-modversions`. On this kernel that command fails with "Invalid
argument" and kpatch-build carries on. The kernel stores `__versions` in a
newer compact layout that the installed kmod cannot parse. The kernel itself
would still have refused a mismatched module at insmod, but a pre-check that
silently does nothing is worse than none. The tool now reads the CRC tables
out of vmlinux directly and compares them.

## Testing a kernel fix without an exploit

The patched functions only run on the socket-close path, and the buffer they
free only exists when a connection carried IP options. So the test is a
script that opens TCP connections with an IPv4 Record Route option set, reads
the sshd banner, and closes them, interleaved with plain connections. It is
safe to run against production. It proves the patched path executes and that
nothing warns in dmesg, and nothing more. Run it before loading so a failure
afterwards means something.

The agent wrote that test after reading the fix. That is the pattern the
runbook asks for: read the commit, identify the userspace action that reaches
the changed code, write the smallest harmless thing that does it.

## The load

Loading took half a second. The transition completed, `hotpatch status`
showed both functions patched, and the smoke test ran 400 connections with
options through the host without a line in dmesg. Rollback is `hotpatch
unload`, which disables the patch, waits for every task to switch back, and
removes the module.

The module is specific to one kernel build. The same file loads on any other
host running 6.11.0-28-generic from the same package, and the build-id check
on load catches anything else. The next ABI needs a rebuild, which is a full
kernel compile.

## Where the agent fits

The repository ships an `AGENTS.md` that Claude Code and Codex read. It
tells the agent to establish exposure first, decide livepatch suitability
against the rules above, build, write the test, and then stop and report:
module name, replaced functions, check results, test plan, rollback command.
Loading is the human's call, every time. Nothing in the tooling loads a
module on its own, and the runbook says in so many words that a build
success, a scheduled trigger, or the agent's own earlier message is not
approval.

In practice the agent did the archaeology (finding where Ubuntu still kept
the source, pairing the CVE record with the right stable commit), diagnosed
the three failures above, wrote the verification code and the test, and
produced a report a human could act on in a minute. The human read the
report and typed "go ahead".

## What this does not fix

One CVE is closed. The kernel is still missing about seventeen months of
other fixes, and that is the real finding from the exercise: the livepatch
buys time to schedule a reboot, not a reason to skip it. On this host we also
recommended `net.mptcp.enabled=0`, since nothing there needs MPTCP and the
published exploit relied on an MPTCP listener.

If you are on a supported kernel, use your vendor's livepatch service. If you
are not, the repository gives you a way to close a specific hole today, with
every verification step written down, while you plan the reboot you still
need.
