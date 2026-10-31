#!/usr/bin/env python3
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPTS, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


modversions = load("check-modversions")
fixcommits = load("cve-fix-commits")


class FakeElf:
    def __init__(self, data):
        self.data = data

    def section_bytes(self, name):
        assert name == "__versions"
        return self.data


def compact_entry(crc, name):
    body = name.encode() + b"\0"
    size = (8 + len(body) + 3) & ~3
    return struct.pack("<II", size, crc) + body.ljust(size - 8, b"\0")


def legacy_entry(crc, name):
    return struct.pack("<Q", crc) + name.encode().ljust(56, b"\0")


class ModversionsTest(unittest.TestCase):
    def test_compact_layout(self):
        data = compact_entry(0x11223344, "kfree") + compact_entry(0xDEADBEEF, "module_layout") + b"\0" * 5
        self.assertEqual(
            modversions.module_versions(FakeElf(data)),
            {"kfree": 0x11223344, "module_layout": 0xDEADBEEF},
        )

    def test_legacy_layout(self):
        data = legacy_entry(0x11223344, "kfree") + legacy_entry(0xDEADBEEF, "module_layout")
        self.assertTrue(modversions.legacy_layout(data))
        self.assertEqual(
            modversions.module_versions(FakeElf(data)),
            {"kfree": 0x11223344, "module_layout": 0xDEADBEEF},
        )

    def test_compact_entry_is_not_mistaken_for_legacy(self):
        data = compact_entry(0x11223344, "a" * 52)
        self.assertEqual(len(data) % 64, 0)
        self.assertFalse(modversions.legacy_layout(data))

    def test_malformed_compact_entry(self):
        data = struct.pack("<II", 6, 0) + b"xx"
        with self.assertRaises(SystemExit):
            modversions.module_versions(FakeElf(data))


def record(commits, branches):
    versions = [{"version": "0", "lessThan": "4.4", "status": "unaffected", "versionType": "semver"}]
    for c in commits:
        versions.append({"version": "079096f1", "lessThan": c, "status": "affected", "versionType": "git"})
    for b in branches[:-1]:
        versions.append({"version": b, "lessThanOrEqual": b.rsplit(".", 1)[0] + ".*",
                         "status": "unaffected", "versionType": "semver"})
    versions.append({"version": branches[-1], "lessThanOrEqual": "*", "status": "unaffected",
                     "versionType": "original_commit_for_fix"})
    return {"containers": {"cna": {"affected": [{"versions": versions}]}}}


class FixCommitsTest(unittest.TestCase):
    commits = ["a" * 40, "b" * 40, "c" * 40, "d" * 40]
    branches = ["6.6.159", "6.12.113", "6.18.56", "7.3"]

    def test_nearest_branch_first(self):
        pairs = fixcommits.fix_commits(record(self.commits, self.branches))
        ordered = fixcommits.order(pairs, "6.11.0-28-generic")
        self.assertEqual([b for _, b in ordered], ["6.12.113", "6.6.159", "6.18.56", "7.3"])
        self.assertEqual(ordered[0][0], "b" * 40)

    def test_count_mismatch_leaves_branches_unlabeled(self):
        rec = record(self.commits, self.branches)
        rec["containers"]["cna"]["affected"][0]["versions"].pop()
        pairs = fixcommits.fix_commits(rec)
        self.assertEqual({b for _, b in pairs}, {"unknown"})
        self.assertEqual(len(pairs), 4)

    def test_branch_label_cannot_inject_rows(self):
        rec = record(["a" * 40], ["7.3\n" + "b" * 40 + " evil"])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(rec, f)
        try:
            out = subprocess.run([sys.executable, "-I", os.path.join(SCRIPTS, "cve-fix-commits.py"), f.name, "6.11.0"],
                                 capture_output=True, text=True, check=True).stdout
        finally:
            os.unlink(f.name)
        self.assertEqual(out.splitlines(), ["a" * 40 + " unknown"])

    def test_main_rejects_bad_commit(self):
        rec = record(["zz" * 20], ["7.3"])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(rec, f)
        try:
            sys.argv = ["x", f.name, "6.11.0"]
            with self.assertRaises(SystemExit):
                fixcommits.main()
        finally:
            os.unlink(f.name)


inspect = load("inspect-patch")

SYNTHETIC = """\
From 0123456789abcdef0123456789abcdef01234567 Mon Sep 17 00:00:00 2001
Subject: [PATCH 5.15] net: widen struct foo
 and the rest of the subject

Body line one.

Signed-off-by: Someone <s@example.org>
---
diff --git a/include/net/foo.h b/include/net/foo.h
--- a/include/net/foo.h
+++ b/include/net/foo.h
@@ -1,3 +1,4 @@
 struct foo {
 	int a;
+	int b;
 };
diff --git a/net/foo/bar.c b/net/foo/bar.c
--- a/net/foo/bar.c
+++ b/net/foo/bar.c
@@ -1,2 +1,3 @@
+static int table[4];
 #include <net/foo.h>
 
@@ -6,9 +7,9 @@ static int first(void)
 static void second(struct request *req)
 {
-	kfree(req->opt);
+	kfree_rcu(req->opt, rcu);
 }
 
 static int __init foo_init(void)
 {
-	return 0;
+	return 1;
 }
"""

BAR_C = """\
#include <net/foo.h>

static int first(void)
{
	return 0;
}
static void second(struct request *req)
{
	kfree(req->opt);
}

static int __init foo_init(void)
{
	return 0;
}
static int
leading_name(void)
{
	return 0;
}
"""


class InspectTest(unittest.TestCase):
    def test_curated_patch_header_fallback(self):
        with open(os.path.join(HERE, "..", "patches", "CVE-2026-98432.patch")) as f:
            lines = f.read().splitlines()
        subject, body = inspect.git_header(lines)
        self.assertEqual(subject, "ipv4: free inet_opt and ireq_opt after an RCU grace period")
        self.assertIn("Signed-off-by", body)
        files = inspect.annotate(inspect.parse(lines), None)
        self.assertEqual(sorted(files), ["net/ipv4/af_inet.c", "net/ipv4/tcp_ipv4.c"])
        self.assertEqual(files["net/ipv4/af_inet.c"]["funcs"], ["inet_sock_destruct"])
        self.assertEqual(inspect.review(files), [])

    def test_functions_from_source(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "net/foo"))
            os.makedirs(os.path.join(d, "include/net"))
            with open(os.path.join(d, "net/foo/bar.c"), "w") as f:
                f.write(BAR_C)
            with open(os.path.join(d, "include/net/foo.h"), "w") as f:
                f.write("struct foo {\n\tint a;\n};\n")
            lines = SYNTHETIC.splitlines()
            subject, _ = inspect.git_header(lines)
            self.assertEqual(subject, "net: widen struct foo and the rest of the subject")
            files = inspect.annotate(inspect.parse(lines), d)
            bar = files["net/foo/bar.c"]
            self.assertTrue(bar["from_source"])
            self.assertEqual(bar["funcs"], ["second", "foo_init"])
            self.assertEqual(bar["unanchored"], 1)
            self.assertEqual(inspect.enclosing_block(BAR_C.splitlines(), len(BAR_C.splitlines()) - 1),
                             ("func", "leading_name", "leading_name(void)"))
            self.assertEqual(inspect.enclosing_block(["static void *ptr_fn(int a)", "{", "\tx;"], 3)[1], "ptr_fn")
            self.assertEqual(inspect.enclosing_block(["}", "EXPORT_SYMBOL(ptr_fn)", "", "int next(void)", "{", "\tx;"], 6)[1], "next")
            self.assertEqual(inspect.enclosing_block(["}", "EXPORT_SYMBOL(ptr_fn)", "static int x;"], 3)[0], None)
            text = "\n".join(inspect.review(files))
            self.assertIn("include/net/foo.h: header change", text)
            self.assertEqual(files["include/net/foo.h"]["types"], ["foo"])
            self.assertIn("changes the definition of foo", text)
            self.assertIn("foo_init is init or exit code", text)
            self.assertIn("1 changed line(s) outside any function", text)

    def test_hunk_offset_is_located_in_source(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "net/foo"))
            with open(os.path.join(d, "net/foo/bar.c"), "w") as f:
                f.write("/* a */\n/* b */\n/* c */\n" + BAR_C)
            files = inspect.annotate(inspect.parse(SYNTHETIC.splitlines()), d)
            bar = files["net/foo/bar.c"]
            self.assertEqual(bar["funcs"], ["second", "foo_init"])
            self.assertEqual(bar["unanchored"], 1)

    def test_hunk_with_differing_context_is_still_located(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "net/foo"))
            with open(os.path.join(d, "net/foo/bar.c"), "w") as f:
                f.write(BAR_C.replace("\treturn 0;\n}\nstatic int\n", "\treturn 0;\n} /* changed trailing context */\nstatic int\n"))
            files = inspect.annotate(inspect.parse(SYNTHETIC.splitlines()), d)
            self.assertEqual(files["net/foo/bar.c"]["funcs"], ["second", "foo_init"])

    def test_hunk_header_fallback_names_wrong_function(self):
        files = inspect.annotate(inspect.parse(SYNTHETIC.splitlines()), None)
        self.assertFalse(files["net/foo/bar.c"]["from_source"])
        self.assertEqual(files["net/foo/bar.c"]["funcs"], ["first"])

    def test_locate(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "net/ipv4"))
            with open(os.path.join(d, "net/ipv4/Makefile"), "w") as f:
                f.write("obj-y := route.o \\\n\taf_inet.o tcp_ipv4.o\n"
                        "obj-$(CONFIG_TCP_CONG_BBR) += tcp_bbr.o\n"
                        "obj-$(CONFIG_NET_FOO) += foo.o\nfoo-y := foo_main.o foo_util.o\n")
            cfg = os.path.join(d, "config")
            with open(cfg, "w") as f:
                f.write("CONFIG_TCP_CONG_BBR=m\nCONFIG_NET_FOO=y\n")
            self.assertTrue(inspect.locate(d, cfg, "net/ipv4/af_inet.c").startswith("built into vmlinux"))
            self.assertTrue(inspect.locate(d, cfg, "net/ipv4/tcp_bbr.c").startswith("module tcp_bbr"))
            self.assertIn("CONFIG_NET_FOO=y", inspect.locate(d, cfg, "net/ipv4/foo_util.c"))
            self.assertEqual(inspect.locate(d, cfg, "net/ipv4/nope.c"), "not found in Makefile")
            with open(os.path.join(d, "net/ipv4/Makefile"), "a") as f:
                f.write("obj-$(CONFIG_OTHER) += x-zap.o\nobj-$(CONFIG_ZAP) += zap.o\n")
            with open(cfg, "a") as f:
                f.write("CONFIG_OTHER=y\nCONFIG_ZAP=n\n")
            self.assertEqual(inspect.locate(d, cfg, "net/ipv4/zap.c"), "not built (CONFIG_ZAP=n)")

    def test_repeated_file_sections_keep_all_hunks(self):
        twice = SYNTHETIC + "diff --git a/net/foo/bar.c b/net/foo/bar.c\n--- a/net/foo/bar.c\n+++ b/net/foo/bar.c\n@@ -1,2 +1,3 @@\n+int again;\n #include <net/foo.h>\n \n"
        files = inspect.annotate(inspect.parse(twice.splitlines()), None)
        self.assertEqual(len(files["net/foo/bar.c"]["hunks"]), 3)
        self.assertEqual(files["net/foo/bar.c"]["unanchored"], 2)


catalog = load("cve-catalog")


def cna_record(intro, mainline, branch_fixes, commits=("a" * 40,)):
    versions = [{"version": intro, "status": "affected"},
                {"version": "0", "lessThan": intro, "status": "unaffected", "versionType": "semver"}]
    for c in commits:
        versions.append({"version": "1" * 40, "lessThan": c, "status": "affected", "versionType": "git"})
    for b in branch_fixes:
        versions.append({"version": b, "lessThanOrEqual": b.rsplit(".", 1)[0] + ".*",
                         "status": "unaffected", "versionType": "semver"})
    versions.append({"version": mainline, "lessThanOrEqual": "*", "status": "unaffected",
                     "versionType": "original_commit_for_fix"})
    return {"containers": {"cna": {"affected": [{"versions": versions}]}}}


class CatalogTest(unittest.TestCase):
    rec = cna_record("4.4", "7.3", ["6.6.159", "6.12.113"])

    def test_unsupported_series_between_intro_and_fix_is_affected(self):
        self.assertEqual(catalog.affects(self.rec, (6, 11, 0)), "a" * 40)

    def test_before_introduction_is_not_affected(self):
        self.assertIsNone(catalog.affects(self.rec, (4, 3, 9)))

    def test_mainline_at_or_past_fix_is_not_affected(self):
        self.assertIsNone(catalog.affects(self.rec, (7, 3, 0)))

    def test_stable_branch_fix_covers_newer_point_release(self):
        self.assertIsNone(catalog.affects(self.rec, (6, 6, 160)))
        self.assertEqual(catalog.affects(self.rec, (6, 6, 150)), "a" * 40)

    def test_record_without_fix_commit_is_skipped(self):
        self.assertIsNone(catalog.affects(cna_record("4.4", "7.3", [], commits=()), (6, 11, 0)))

    def test_main_reads_ids_and_records(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "cve/published/2026"))
            rec = cna_record("4.4", "7.3", ["6.6.159"])
            rec["cveMetadata"] = {"cveId": "CVE-2026-1234"}
            rec["containers"]["cna"]["title"] = "net: fix thing"
            with open(os.path.join(d, "cve/published/2026/CVE-2026-1234.json"), "w") as f:
                json.dump(rec, f)
            ids = os.path.join(d, "ids")
            with open(ids, "w") as f:
                f.write("CVE-2026-1234\nCVE-2026-9999\nnot-an-id\n")
            r = subprocess.run([sys.executable, "-I", os.path.join(SCRIPTS, "cve-catalog.py"), d, "6.11.0-28-generic", ids],
                               capture_output=True, text=True, check=True)
            self.assertEqual(r.stdout.splitlines()[0], "CVE-2026-1234\t" + "a" * 40 + "\tnet: fix thing")
            self.assertTrue(r.stdout.splitlines()[1].startswith("CVE-2026-9999\t-\tno record"))

    def test_object_names(self):
        self.assertEqual(inspect.object_name("built into vmlinux (obj-y=y)"), "vmlinux")
        self.assertEqual(inspect.object_name("module tcp_bbr (CONFIG_TCP_CONG_BBR=m), loaded: yes"), "module:tcp_bbr:loaded")
        self.assertEqual(inspect.object_name("module tcp_bbr (CONFIG_TCP_CONG_BBR=m), loaded: no"), "module:tcp_bbr")
        self.assertEqual(inspect.object_name("not built (CONFIG_X=n)"), "not-built")


if __name__ == "__main__":
    unittest.main()
