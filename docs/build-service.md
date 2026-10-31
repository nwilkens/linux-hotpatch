# An open livepatch build service for every kernel

Status: proposal. Nothing in this document is built yet except the client,
which is the `hotpatch` tool in this repository.

## The problem

Every vendor livepatch service covers its own kernels, for a limited time,
for the CVEs it selects, as one cumulative module. Everything outside that
box gets a reboot or nothing: kernels past vendor support, HWE and cloud
flavours after their window, self-built kernels, distributions without a
service, and any CVE the vendor rated below its threshold. The commercial
cross-distro services close part of the gap at a price, with build pipelines
nobody outside can inspect or rerun.

The proposal is a service with the same shape as the commercial ones and
three differences: every input, recipe, review, test result and build log is
public and the build can be repeated by anyone; any kernel with
`CONFIG_LIVEPATCH` is in scope, including ones nobody supports; and each fix
is its own module where the fixes are independent, so one bad patch can come
out alone.

## What the incumbents do

| Service | Kernels | Window per kernel | Selection | Shape | Notable |
|---|---|---|---|---|---|
| SUSE KLP | SLE | 13 months | CVSS 7+ and stability fixes | cumulative, one loaded at a time | empty seed patch shipped with each kernel, active patch in initrd so it survives a reboot, `klp downgrade`, source-level extraction with klp-ccp, built on an internal build service |
| Red Hat kpatch | RHEL | 6 months, 12 on EUS | selected Important and Critical | cumulative RPMs, kept installed by kpatch-dnf | revert without reboot unsupported, third-party livepatches unsupported |
| Canonical Livepatch | Ubuntu GA and latest HWE, Pro only | HWE 6 to 9 months | High and Critical | cumulative | signed modules verified by the client, staged rollout tiers, patches tied to a crash are suppressed, on-prem server for air gap, cert enrolled via MOK |
| Amazon Linux | AL2, AL2023 | months per kernel version | vendor selected | kpatch modules via package manager | free, reloaded at boot by kpatch.service |
| Debian | none | | | | kernel ships `CONFIG_LIVEPATCH=y`, no service |
| Oracle Ksplice | Oracle Linux, OCI, Ubuntu desktop free | vendor support life | vendor selected | signed updates, all-or-nothing removal | userspace patching, effective `uname`, known exploit detection |
| TuxCare KernelCare | RHEL family, Ubuntu, Debian, Amazon, Proxmox, EOL distros via ELS | until vendor advisories stop plus a year | all vendor-patched CVEs, 10-day target | binary per kernel, rolling | about four dollars per server per month, feeds and sticky dates, ePortal for air gap, `/proc/kcare/effective_version` for scanners, standard kernels only |
| elivepatch (Gentoo, 2017) | any, custom configs | | user supplied | kpatch-build on a server | client posts config plus diff over REST, warned that arbitrary diffs cannot be trusted, dormant |

What to take from each:

- SUSE: persistence across an unexpected reboot, a downgrade path, published
  expiry dates, and source-level extraction for the cases binary diffing
  handles badly.
- Red Hat and Canonical: a severity-driven default selection, staged rollout
  so a bad build hits a canary tier first, and suppression of a patch that
  was active when the host crashed.
- Ksplice and KernelCare: broad distro coverage including end-of-life
  kernels, a machine-readable effective patch level for scanners, air-gapped
  mirrors, a published turnaround target.
- elivepatch: the request-and-build model, and its lesson that a public
  builder must never compile a diff it did not resolve itself.

## Design

### Identity

The client reads the GNU build-id of the running vmlinux from
`/sys/kernel/notes`. It is the lookup key: it finds the target manifest for
this kernel build. It is not the identity of an artifact. A build-id can be
absent, chosen by the builder, or shared by two differently linked kernels,
and it says nothing about the separately built `.ko` files a patch might
target. So:

- The target manifest for a kernel build records the vmlinux build-id, the
  kernel package name and version, the toolchain, the config hash, and the
  build-id or sha256 of every module file under `/lib/modules` that any
  published patch replaces functions in.
- An artifact is keyed by the digest of its complete recipe (target manifest,
  source package hashes, toolchain image digest, builder tool commit, make
  flags) plus the ordered set of patch hashes it carries. A re-resolved fix
  is a new artifact.
- A kernel without a usable build-id gets no automatic match. `uname`,
  vermagic and symbol CRCs are checked but are not accepted as a substitute,
  since all three survive a rebuild from different source.
- Patches whose targets are modules rather than vmlinux are a later phase.
  The first service is vmlinux-only and says so in the catalog.

### Client

The existing `hotpatch` tool gains a few commands.

`hotpatch fingerprint` prints the submission: architecture, `uname -r`,
vermagic, build-id, distro id and version, kernel package name and version
from dpkg or rpm, the compiler string from `/proc/version`, a hash of the
kernel config, whether Secure Boot and lockdown are on, and whether
`/sys/kernel/livepatch` exists. No hostname, no addresses, no module list,
no process list. The user reads it before sending it.

`hotpatch sync` fetches the signed catalog for the host's target manifest:
for each CVE, one of available, queued, building, not affected, unsuitable
with the reason, or withdrawn. It downloads an artifact on request together
with its manifest, attestation, review note, test record and smoke script,
and verifies every one locally before `load` will touch it: signature from
the expected signer identity, attestation bound to this target manifest,
catalog freshness, build-id, CRCs against the debug vmlinux when present,
and the changed-function list against the manifest.

`hotpatch request CVE-...` asks the service to build a patch that the
catalog lists for this series but not yet for this target.

`hotpatch status --json` and an OpenVEX document distinguish three states a
scanner needs: a fix is available for this kernel, a module is loaded, and
the transition finished so the fix is in effect. A livepatch does not change
`uname`, so this is the only evidence a scanner can use.

### Resolver

The service maps a fingerprint to a recipe: where the exact source package
is, where the debug symbols are, which toolchain packages built it, and
which flags the distribution passed on the make command line. This is the
backend contract already in `lib/backend/`, run centrally instead of on the
host. Sources are distro snapshot archives, which keep packages after the
live pool drops them: Launchpad and snapshot.ubuntu.com, snapshot.debian.org,
Fedora koji, the CentOS and Rocky vaults, the Amazon Linux repositories.

A fingerprint the resolver does not know becomes a recipe request. For a
distro kernel that means a contributor writes or fixes a backend. For a
self-built kernel the submitter supplies the source tree, the config and a
container image holding the toolchain that built it. Such builds run only
on a self-hosted instance or under the submitter's own signing key. The
public instance never signs an artifact built from a toolchain or source it
did not obtain from a distribution archive, because an attacker-supplied
compiler produces the same malicious module on every builder.

### Builders

Two patch generators exist and the service needs both. kpatch-build is in
maintenance mode from Linux 6.19 and will not gain support for newer
kernels or toolchains, which leaves it exactly the tool for the older
kernels this service exists for. The in-tree `scripts/livepatch/klp-build`
covers x86-64 from 6.19 with other architectures following. The builder
interface takes a target manifest and a patch set and hides which generator
ran.

A build job is one artifact. Builders are disposable containers pinned by
digest, one image per distribution release, with the toolchain installed
from the snapshot archive at the version the kernel package records. A
builder has network access only during the fetch step and only to the
archive hosts, verifies what it fetched the way the tool does today (signed
release files, dsc checksums, build-id of the debug vmlinux against the
target), and holds no credential that reaches the catalog or the signer.

The expensive step is the first compile of the unpatched tree, about an
hour on four cores. kpatch-build keeps that tree in its cache directory and
reuses it, so the second CVE for the same target takes minutes. The service
keeps warm trees per target as a performance cache, evicts cold ones, and
rebuilds on demand.

Every published artifact is built twice, by builders with separate images,
caches, credentials and operators, one of them from a cold tree. The
unsigned module files must be byte-identical. Nothing is stripped to make
them agree; if the kernel's reproducible-build controls (fixed timestamp,
user, host and paths) are not enough for a recipe, that recipe is not
publishable until the cause is found. The agreed unsigned digest and the
delivered signed digest are both recorded.

Each build ends with the checks the tool already performs plus one: the
changed-function list must match what `inspect` derived from the source
diff, and every extra function must be explained in the review note, or
the build is held.

### Composition

One module per CVE is the default, not a promise. The catalog records, per
artifact, the functions it replaces and the artifacts it conflicts with.
Two fixes that touch the same function are published as one combined
artifact for that pair, listed under both CVEs. Fixes with disjoint
functions can still depend on each other through locking or object lifetime
changes; the reviewer states whether a patch may be loaded without, or
unloaded before, another, and the catalog carries that as an ordering
constraint. The client refuses a load or unload that violates one.

### Review

Suitability has two parts. The semantic review is done once per (CVE,
kernel series): the risk statement, the verdict, the explanation of extra
functions, cross-patch constraints, whether unloading is safe once the
patch has run, and the smoke script. A maintainer signs it. The
qualification is done per target automatically: config options that
remove or change the affected code, compiler decisions visible in the
changed-function list, ftrace coverage of every replaced function on that
kernel, architecture. An artifact carries both, and a target that fails
qualification is published as unsuitable with the reason.

Selection follows the vendors by default, CVSS 7 and above plus anything a
maintainer flags, and everything else on request. The kernel CNA issues
several hundred CVEs a month; on one 6.11 kernel the October 2026 set
resolved to 461 applicable patches and 141 needing review, so the request
path matters more than the pre-build list.

### Test

Every published artifact is loaded in a virtual machine running the
identical kernel package, booted from the distribution's own kernel image
and a minimal initramfs. Load, wait for the transition, run the smoke
script, run a fixed stress set for a few minutes, unload, check dmesg.

A smoke script that passes before and after the patch proves only that the
path still works, so the test also proves the path ran: the replaced
functions are traced through ftrace, filtered to the livepatch module, and
the test fails if any of them recorded zero hits during the smoke script.
Where the CVE has a safe regression test, for example a KASAN-visible
use-after-free with no exploit value, the test runs it on a KASAN build of
the same source before and after. Published combinations are tested as
combinations, including the unload order the composition metadata allows.

Kernels the service cannot boot, which means most self-built ones, are not
published by the public instance.

### Signing and catalog

Artifacts are signed with the service's module signing key, held in an HSM
and used by a signer that sees only artifacts whose policy binding checks
out: approved recipe, approved patch set, signed review note, passing test
record, two matching builder attestations from the expected builder
identities. The key authorizes whatever it signs on every enrolled host, so
no exception path exists for experimental artifacts.

Hosts with Secure Boot enroll the certificate through MOK once, which costs
one reboot, the same as every vendor service. Sites that prefer their own
key run `hotpatch resign` with the kernel's `sign-file`, which produces a
new artifact identity recorded beside the original.

Each artifact carries a SLSA provenance statement signed with Sigstore and
logged in Rekor. The client verifies the expected signer identity and
issuer, not merely a valid signature.

The catalog itself follows the TUF model: signed, versioned, with an
expiry, with a withdrawal list, and the client refuses a catalog older than
the one it last saw. A mirror or CDN can delay a catalog until it expires;
it cannot replay an old one or hide a withdrawal inside a fresh one. Export
bundles for air-gapped hosts carry the catalog with its expiry, and the
site decides how stale a bundle may be.

### Distribution and persistence

Published artifacts are a static tree keyed by target in an object store
behind a CDN. Nothing dynamic sits in the download path. An on-prem mirror
is a copy of the subtree for the targets a site runs. Rollout follows
tiers: an artifact is visible to canary subscribers first, then to everyone
after a quiet period with no reports.

Desired state is recorded when a module is enabled, not at shutdown, since
an unexpected reboot skips shutdown. On boot, if the same target manifest
is running, the recorded modules are reloaded in the recorded order. A boot
that follows a crash within a short window after a load marks that module
suspect and leaves it unloaded until an operator clears it. This is weaker
than SUSE's initrd placement, which has the patch active before userspace
starts; closing that window on distributions whose initramfs tooling allows
it is later work.

### Operations

Operators of the commercial services expect, and this one must publish: a
maintained support matrix per distribution, kernel and architecture; a
turnaround target from CVE publication to artifact; an emergency withdrawal
path that reaches clients through the catalog within one sync interval;
rollout stop criteria tied to canary reports; and an escalation path for a
patch whose unload is unsafe, which ends in a scheduled reboot.

All code, recipes, review notes, patches, test scripts, build logs and
attestations live in public git and public storage. The service is
self-hostable in full; the public instance is a shared cache and a
convenience, not a dependency. Operating cost is small: a prepared tree is
a few core-hours once per target, a CVE build on a warm tree is minutes, a
cold rebuild for the dual check is the same few core-hours, a VM test is
minutes. Tracking a thousand targets at thirty patches a month each is on
the order of fifty cores running continuously plus storage for warm trees.
Priority queueing, support contracts and hosted mirrors are the things
worth charging for; the artifacts are not.

## Threats

Imagine the attacker's goal is a module of their choosing loaded on
someone's host.

- Submitted fingerprints are data. Every field is validated against a
  schema; nothing from a submission reaches a shell.
- The public instance builds only patches it resolved itself from the
  kernel CNA record or that a maintainer committed under `patches/`, from
  source and toolchains it fetched from distribution archives over signed
  indexes. User-supplied diffs, trees and toolchains are self-hosted
  features.
- A compromised builder cannot publish alone: the second builder shares no
  image, cache, credential or operator with it, and the signer checks the
  policy binding before signing.
- A compromised CDN or mirror can withhold but not forge, replay or
  selectively suppress: the client checks signer identity, catalog version,
  catalog expiry and the withdrawal list offline.
- The signing key never leaves the HSM, and the signer is a separate service
  with its own audit log; the rotation procedure, which touches every
  enrolled host, is written and rehearsed before the first signature.
- Build requests are rate limited and prioritised by account.
  Unauthenticated requests can only ask for CVEs the catalog already lists
  for that series.

## Limits

- The kernel must have `CONFIG_LIVEPATCH=y` and ftrace with registers or
  arguments. That is roughly 4.x and later on x86_64 and the vendor kernels
  that backported it. The 2.6.32 and 3.x era that Ksplice and KernelCare
  reach needs their proprietary mechanisms and is out of scope.
- Architectures follow the generators: x86_64 first, then arm64, ppc64le
  and s390x.
- Fixes that change struct layout, init code, or exported symbols need a
  reboot. The review publishes that verdict instead of a module.
- Third-party modules such as out-of-tree filesystems and GPU drivers are
  not covered.
- Secure Boot hosts need one reboot to enroll the certificate.
- A livepatch is a bridge to the next reboot, not a substitute for it.

## Phases

1. Prove the core on one distribution, one architecture and a handful of
   kernel builds: target manifests, artifact keys, dual-build
   reproducibility measured rather than assumed, per-target qualification,
   composition metadata, VM tests with ftrace hit evidence. Nothing
   published, nothing signed.
2. Signer, HSM, MOK certificate, Sigstore attestations, TUF catalog with
   expiry and withdrawal, boot persistence with crash suppression, status
   and OpenVEX output. Rehearse key rotation and withdrawal.
3. Publish for the phase 1 kernels behind a canary tier, then open the
   request queue and add the second and third distributions.
4. The klp-build generator for 6.19 and later, arm64, module targets,
   on-prem mirror tooling, initramfs placement where possible, and
   self-hosted support for custom kernels last.
