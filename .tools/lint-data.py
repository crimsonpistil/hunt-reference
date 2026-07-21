#!/usr/bin/env python3
"""
TONK data linter.

Checks the hunt-reference data files for the bug classes that are invisible
in the browser but break downstream consumers (Sigma export, SIEM paste,
future iteration). Run before committing data changes.

Checks
------
  sparse-array   stray `},` + `,` creating a JS array hole. forEach skips
                 holes so the site looks fine, but DATA.length is wrong and
                 for..of throws.
  bad-regex      a /regex/ literal that does not compile after JS string
                 unescaping. Usually one backslash too few in the source:
                 JS silently eats `\\^` into `^`.
  commented-out  a query written inside its own comment (`// Windows: foo: bar`).
                 Renders fine, but is not pasteable and never reaches export.
  lost-block     a `// Label` header directly following query content with no
                 blank line. Treated as a trailing annotation, so the query
                 under it is silently swallowed into the previous block.
  raw-control    literal control bytes in a value. Prefer \\uXXXX escapes.

Exit code is 0 when clean, 1 when any finding is reported.

Usage:
  python3 .tools/lint-data.py
  python3 .tools/lint-data.py --quiet
"""

import argparse
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

spec = importlib.util.spec_from_file_location(
    "sigma_export", os.path.join(HERE, "sigma-export.py"))
sx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sx)

QUERY_FIELDS = ("kibana", "arkime", "suricata", "sysmon", "powershell")

RE_LITERAL = re.compile(r"/\((.+?)\)/", re.S)
COMMENTED_QUERY = re.compile(
    r"^\s*//\s*([A-Za-z][A-Za-z0-9 .\-]{0,18}?)\s*:\s*"
    r"([a-z][\w@\-]*(?:\.[\w@\-]+)+\s*:\s*\S.*)$")
HOLE = re.compile(r"\},\s*\n\s*,\s*\n")


def data_files():
    for domain in ("net", "host"):
        d = os.path.join(REPO, domain, "js", "data")
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".js"):
                yield domain, fn, os.path.join(d, fn)


def lint():
    findings = []

    def add(kind, path, tech, field, detail):
        findings.append((kind, os.path.relpath(path, REPO), tech, field, detail))

    for _domain, _fn, path in data_files():
        raw = open(path, encoding="utf-8").read()

        for ch in raw:
            if ord(ch) < 32 and ch not in "\n\t\r":
                add("raw-control", path, "-", "-",
                    "literal U+%04X byte in source (use a \\uXXXX escape)"
                    % ord(ch))
                break

        if HOLE.search(raw):
            add("sparse-array", path, "-", "-",
                "stray double comma creates a JS array hole")

        try:
            data = sx.load_data_file(path)
        except Exception as exc:                          # noqa: BLE001
            add("parse-error", path, "-", "-", str(exc))
            continue

        for tech in data:
            tid = tech.get("id", "?")
            for row in tech.get("rows", []):
                for field in QUERY_FIELDS:
                    val = row.get(field)
                    if not isinstance(val, str) or not val:
                        continue

                    for m in RE_LITERAL.finditer(val):
                        pat = m.group(1)
                        if "\n" in pat:      # display-wrapped Suricata pcre
                            continue
                        try:
                            re.compile(pat)
                        except re.error as exc:
                            add("bad-regex", path, tid, field,
                                "%s -- %s" % (exc, pat[:60]))

                    lines = val.split("\n")
                    for idx, line in enumerate(lines):
                        m = COMMENTED_QUERY.match(line)
                        if m and ":" in m.group(2):
                            add("commented-out", path, tid, field,
                                "query inside comment: %s" % line.strip()[:60])
                        if (field == "kibana"
                                and re.match(r"^\s*//", line) and idx > 0
                                and lines[idx - 1].strip()
                                and not re.match(r"^\s*//", lines[idx - 1])):
                            nxt = lines[idx + 1] if idx + 1 < len(lines) else ""
                            if nxt.strip() and not re.match(r"^\s*//", nxt):
                                add("warn-lost-block", path, tid, field,
                                    "no blank line before header %s"
                                    % line.strip()[:48])
    return findings


def main():
    ap = argparse.ArgumentParser(description="Lint TONK data files.")
    ap.add_argument("--quiet", action="store_true",
                    help="print only the summary line")
    args = ap.parse_args()

    findings = lint()
    if not args.quiet:
        by_kind = {}
        for f in findings:
            by_kind.setdefault(f[0], []).append(f)
        for kind in sorted(by_kind):
            items = by_kind[kind]
            print("\n%s (%d)" % (kind.upper(), len(items)))
            for _k, path, tech, field, detail in items:
                print("  %-34s %-11s %-10s %s" % (path, tech, field, detail))

    print("\n%d finding(s)" % len(findings) if findings else "\nclean - 0 findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
