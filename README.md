# linux-hotpatch

Builds kernel livepatch modules for the running Ubuntu kernel with
[kpatch](https://github.com/dynup/kpatch) and loads them without a reboot.

Source and debug symbols come from Launchpad, which still serves packages the
archive pool has dropped, so end-of-life HWE kernels can be patched. The debug
vmlinux is checked against the running kernel's GNU build-id before use.

## Use

    scripts/deploy.sh root@host ~/.ssh/key   # copy to /root/linux-hotpatch
    ./hotpatch deps
    ./hotpatch prepare
    ./hotpatch build cve_2026_98432 patches/CVE-2026-98432.patch
    ./hotpatch load /var/lib/linux-hotpatch/out/cve_2026_98432/cve_2026_98432.ko
    ./hotpatch status
    ./hotpatch unload cve_2026_98432

State lives under `/var/lib/linux-hotpatch` (override with `HOTPATCH_WORKDIR`).
Extra arguments after the patch path go to kpatch-build, for example
`--skip-compiler-check` when the local gcc is a later packaging revision of the
one that built the kernel.

## Patches

- `patches/CVE-2026-98432.patch`: upstream e3f33b0a1d89, "ipv4: free inet_opt
  and ireq_opt after an RCU grace period".
