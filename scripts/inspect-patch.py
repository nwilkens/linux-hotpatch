#!/usr/bin/env python3
"""Summarise a kernel patch for livepatch review.

Prints the commit message, the files and functions it touches, where each
file lands (vmlinux or a module, and whether that module is loaded), and a
list of review items: constructs a livepatch cannot carry or that need a
closer look. With --src the changed functions are found by reading the
source, which is more reliable than the names in hunk headers.

usage: inspect-patch.py [--src SRC_TREE] [--config CONFIG] <patch>
"""
import argparse
import os
import re
import subprocess
import sys

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,(\d+))? @@ ?(.*)$")
# A function name followed by "(", optionally after storage class, return
# type and pointer stars; also matches when the name starts the line.
DEFINITION = re.compile(r"^(?=[A-Za-z_])(?:[\w\*\s]*?[\s\*])?(\w+)\s*\(")
FUNC_CTX = DEFINITION
TYPE_OPENER = re.compile(r"^(?:typedef\s+)?(?:struct|union|enum)\s*(\w+)?\s*\{")
NOT_DEFINITION = re.compile(r"^(?:struct|union|enum|typedef|return|else|if|for|while|switch|do|case)\b|^#|;\s*$|^\s*$")
INIT_FUNC = re.compile(r"\b__init\b|\b__exit\b|\b__ref\b")
REVIEW = [
    (r"\b__init\b|\b__exit\b|\b__initdata\b|_initcall\(|module_init\(|module_exit\(",
     "touches init or exit code, which has already run and cannot be livepatched"),
    (r"^\s*struct\s+\w+\s*\{|^\s*union\s+\w+\s*\{|^\s*enum\s+\w+\s*\{",
     "changes a type definition; layout changes need shadow variables or a reboot"),
    (r"\bstatic\s+(?:__always_)?inline\b|^\s*#\s*define\b",
     "changes an inline function or macro, so every caller is recompiled and patched"),
    (r"EXPORT_SYMBOL",
     "adds or removes an exported symbol, which a livepatch cannot do"),
    (r"\b__ro_after_init\b|\bDEFINE_PER_CPU\b|\bDEFINE_STATIC_KEY\b",
     "changes read-only-after-init or per-cpu data; new data needs a fresh definition"),
    (r"\b(?:bpf_|BPF_|kfunc|tracepoint|TRACE_EVENT)",
     "touches BPF or tracing hooks; check that no attached program depends on the old shape"),
]


def git_header(lines):
    subject, body, in_body = "", [], False
    for line in lines:
        if line.startswith("diff --git") or line == "---":
            break
        if line.startswith("Subject: "):
            subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", line[9:])
            in_body = True
            continue
        if in_body:
            if line.startswith(" ") and body == []:
                subject += " " + line.strip()
                continue
            body.append(line)
    return subject, "\n".join(body).strip()


def parse(lines):
    """Return {path: {"hunks": [(header_func, [(kind, old_line, text)])]}}."""
    files, current, hunk, old, left = {}, None, None, 0, [0, 0]
    for line in lines:
        if line.startswith("diff --git"):
            current = hunk = None
            continue
        if line.startswith("+++ ") and hunk is None:
            path = line[4:].split("\t")[0]
            current = path[2:] if path.startswith("b/") else path
            files.setdefault(current, {"hunks": []})
            continue
        if current is None:
            continue
        m = HUNK.match(line)
        if m:
            old = int(m.group(1))
            left = [int(m.group(2) or 1), int(m.group(3) or 1)]
            ctx = FUNC_CTX.match(m.group(4))
            hunk = (ctx.group(1) if ctx else None, [])
            files[current]["hunks"].append(hunk)
            continue
        if hunk is None or line.startswith("\\"):
            continue
        if line.startswith("+"):
            hunk[1].append(("+", old, line[1:]))
            left[1] -= 1
        elif line.startswith("-"):
            hunk[1].append(("-", old, line[1:]))
            old += 1
            left[0] -= 1
        else:
            hunk[1].append((" ", old, line[1:]))
            old += 1
            left[0] -= 1
            left[1] -= 1
        if left[0] <= 0 and left[1] <= 0:
            hunk = None
    return files


def enclosing_block(source, lineno):
    """Classify the top-level block containing 1-based lineno.

    Returns ("func", name, line), ("type", name, line) or (None, None, None)
    when the line sits between blocks.
    """
    i = min(lineno, len(source)) - 1
    while i >= 0:
        text = source[i]
        if text.startswith("}"):
            return None, None, None
        m = TYPE_OPENER.match(text)
        if m:
            return "type", m.group(1) or "anonymous", text
        m = DEFINITION.match(text)
        if m and not NOT_DEFINITION.match(text):
            return "func", m.group(1), text
        i -= 1
    return None, None, None


def locate_hunk(source, entries, stated):
    """1-based line where the hunk's old side really sits, or None.

    Like patch(1), tolerate up to two differing context lines at each end.
    """
    kinds = [k for k, _, _ in entries if k != "+"]
    old_lines = [t for k, _, t in entries if k != "+"]
    if not old_lines:
        return stated
    for fuzz in range(3):
        lead = trail = 0
        while lead < fuzz and lead < len(kinds) and kinds[lead] == " ":
            lead += 1
        while trail < fuzz and len(kinds) - trail - 1 > lead and kinds[-1 - trail] == " ":
            trail += 1
        core = old_lines[lead:len(old_lines) - trail]
        n = len(core)
        last = max(0, len(source) - n)
        for i in sorted(range(last + 1), key=lambda i: abs(i - (stated - 1 + lead))):
            if source[i:i + n] == core:
                return i + 1 - lead
    return None


def annotate(files, src):
    """Fill in changed functions, unanchored line counts and changed text."""
    for path, info in files.items():
        funcs, defs, types, unanchored, added, removed = [], {}, [], 0, [], []
        source = None
        if src:
            full = os.path.join(src, path)
            if os.path.isfile(full):
                with open(full, errors="replace") as f:
                    source = f.read().splitlines()
        for header_func, entries in info["hunks"]:
            offset = 0
            hunk_source = source
            if source is not None and entries:
                start = locate_hunk(source, entries, entries[0][1])
                if start is None:
                    hunk_source = None
                else:
                    offset = start - entries[0][1]
            for kind, old, text in entries:
                old += offset
                if kind == "+":
                    added.append(text)
                elif kind == "-":
                    removed.append(text)
                if kind == " ":
                    continue
                if hunk_source is not None:
                    # An added line sits after the previous old line.
                    kind_, name, definition = enclosing_block(hunk_source, old - 1 if kind == "+" and old > 1 else old)
                else:
                    kind_, name, definition = ("func" if header_func else None), header_func, None
                if name is None:
                    unanchored += 1
                elif kind_ == "type":
                    if name not in types:
                        types.append(name)
                elif name not in funcs:
                    funcs.append(name)
                    defs[name] = definition
        info.update(funcs=funcs, defs=defs, types=types, unanchored=unanchored, added=added, removed=removed,
                    from_source=source is not None)
    return files


def config_value(config, sym):
    if not config:
        return None
    with open(config) as f:
        for line in f:
            if line.startswith(sym + "="):
                return line.strip().split("=", 1)[1]
    return "n"


def loaded(module):
    try:
        with open("/proc/modules") as f:
            return any(l.split()[0] == module.replace("-", "_") for l in f)
    except OSError:
        return None


def standalone(obj):
    """Regex for obj as a whole word in a make list, where - is part of names."""
    return r"(?<![\w-])%s(?![\w-])" % re.escape(obj)


def locate(src, config, path):
    """Say whether a .c file is built into vmlinux or a module, via its Makefile."""
    if not src or not path.endswith(".c"):
        return "n/a"
    makefile = os.path.join(src, os.path.dirname(path), "Makefile")
    if not os.path.exists(makefile):
        return "no Makefile found"
    with open(makefile) as f:
        text = f.read().replace("\\\n", " ")
    target = os.path.basename(path)[:-2] + ".o"
    for _ in range(3):
        m = re.search(r"^\s*obj-(?:(y)|\$\((CONFIG_\w+)\))\s*[+:]?=.*%s" % standalone(target), text, re.M)
        if m:
            sym = m.group(2)
            val = "y" if m.group(1) else config_value(config, sym)
            if val == "y":
                return f"built into vmlinux ({sym or 'obj-y'}=y)"
            if val == "m":
                state = loaded(target[:-2])
                return f"module {target[:-2]} ({sym}=m), loaded: {'yes' if state else 'no' if state is False else 'unknown'}"
            return f"not built ({sym}={val})"
        m = re.search(r"^\s*([\w-]+)-(?:y|m|objs|\$\(CONFIG_\w+\))\s*[+:]?=.*%s" % standalone(target), text, re.M)
        if not m:
            return "not found in Makefile"
        target = m.group(1) + ".o"
    return "not found in Makefile"


def object_name(location):
    """Shorten a locate() string to vmlinux, module:<name>[:loaded] or unknown."""
    if location.startswith("built into vmlinux"):
        return "vmlinux"
    m = re.match(r"module (\S+) \(.*loaded: (\w+)", location)
    if m:
        return f"module:{m.group(1)}" + (":loaded" if m.group(2) == "yes" else "")
    if location.startswith("not built"):
        return "not-built"
    return "unknown"


def review(files):
    items = []
    for path, info in files.items():
        changed = info["added"] + info["removed"]
        if path.endswith(".h"):
            items.append(f"{path}: header change; confirm it alters only function bodies, not types or inline helpers used elsewhere")
        if os.path.basename(path) in ("Makefile", "Kbuild") or "Kconfig" in path:
            items.append(f"{path}: build system change, not livepatchable")
        if path.startswith("arch/") and not path.startswith("arch/x86/"):
            items.append(f"{path}: other architecture, irrelevant on x86_64")
        if info["unanchored"] and path.endswith(".c"):
            items.append(f"{path}: {info['unanchored']} changed line(s) outside any function; check for data or declaration changes")
        for name in info["types"]:
            items.append(f"{path}: changes the definition of {name}; layout changes need shadow variables or a reboot")
        for name, definition in info["defs"].items():
            if definition and INIT_FUNC.search(definition):
                items.append(f"{path}: {name} is init or exit code, which has already run and cannot be livepatched")
        for pattern, why in REVIEW:
            hits = [l.strip() for l in changed if re.search(pattern, l)]
            if hits:
                items.append(f"{path}: {why}\n      e.g. {hits[0][:100]}")
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src")
    ap.add_argument("--config")
    ap.add_argument("--brief", action="store_true", help="one line: functions, objects, review count")
    ap.add_argument("patch")
    args = ap.parse_args()
    with open(args.patch, errors="replace") as f:
        lines = f.read().splitlines()
    subject, body = git_header(lines)
    files = annotate(parse(lines), args.src)
    if args.brief:
        funcs = [fn for info in files.values() for fn in info["funcs"]]
        objects = sorted({object_name(locate(args.src, args.config, p)) for p in files})
        items = review(files)
        print(f"funcs={','.join(funcs) or '-'} objects={','.join(objects)} review={len(items)}"
              + (" " + "; ".join(i.split(":", 1)[1].split("\n")[0].strip() for i in items) if items else ""))
        return
    print(f"Subject: {subject}\n")
    if body:
        print(body + "\n")
    print("Files and changed functions" + (":" if args.src else " (from hunk headers, less reliable):"))
    for path, info in files.items():
        print(f"  {path}  +{len(info['added'])} -{len(info['removed'])}  [{locate(args.src, args.config, path)}]")
        for fn in info["funcs"]:
            print(f"    {fn}")
        for t in info["types"]:
            print(f"    type {t}")
    items = review(files)
    print("\nReview items:" if items else "\nReview items: none flagged")
    for item in items:
        print(f"  - {item}")
    if args.src:
        with open(args.patch, "rb") as f:
            r = subprocess.run(["patch", "-p1", "-N", "--dry-run", "-s"], cwd=args.src,
                               stdin=f, capture_output=True, text=True)
        print(f"\nApplies to {args.src}: {'yes' if r.returncode == 0 else 'no'}")
        if r.returncode:
            print((r.stdout + r.stderr).strip())
            sys.exit(1)


if __name__ == "__main__":
    main()
