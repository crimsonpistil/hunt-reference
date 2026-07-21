#!/usr/bin/env python3
"""
TONK -> Sigma exporter.

Converts the TONK hunt reference data files (net/js/data/*.js,
host/js/data/*.js) into a Sigma ruleset. Defensive detection content only.

TONK indicators are hunt logic, not natively Sigma-shaped. This exporter is
deliberately honest about that: every emitted rule carries a fidelity grade.

  full      every clause in the source query translated cleanly into Sigma
  partial   translated, but one or more clauses were approximated or dropped
            (aggregation, ratio math, numeric ranges, inline prose)
  metadata  no machine-translatable logic; the rule is an inert documentation
            stub carrying the original hunt logic for the analyst

Nothing is lost silently. Every dropped clause is recorded per-rule under the
`tonk:` key and summarised in CONVERSION_REPORT.md.

Block splitting mirrors splitBlocks() in js/core.js exactly, so the exporter
and the site agree on what counts as a single query.

Zero third-party dependencies for the core export (air-gap safe).
Optional: --validate runs pySigma over the output if it is installed.

Usage:
  python3 .tools/sigma-export.py
  python3 .tools/sigma-export.py --stats
  python3 .tools/sigma-export.py --out /tmp/out --validate
"""

import argparse
import json
import os
import re
import shutil
import sys
import uuid
from collections import Counter, OrderedDict
from datetime import date

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTHOR = "TONK Hunt Reference (6b74.dev)"
NS = uuid.UUID("6b74d000-0000-4000-8000-000000000001")


class JSParser:
    """Minimal parser for the JSON-like JS object subset used by TONK data."""

    def __init__(self, text):
        self.s, self.i = text, 0

    def error(self, msg):
        raise ValueError("%s at line %d"
                         % (msg, self.s.count("\n", 0, self.i) + 1))

    def ws(self):
        while self.i < len(self.s):
            c = self.s[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif self.s[self.i:self.i + 2] == "//":
                nl = self.s.find("\n", self.i)
                self.i = len(self.s) if nl == -1 else nl + 1
            elif self.s[self.i:self.i + 2] == "/*":
                end = self.s.find("*/", self.i)
                self.i = len(self.s) if end == -1 else end + 2
            else:
                return

    def parse_value(self):
        self.ws()
        if self.i >= len(self.s):
            self.error("unexpected end of input")
        c = self.s[self.i]
        if c == "{":
            return self.parse_object()
        if c == "[":
            return self.parse_array()
        if c in "\"'`":
            return self.parse_string()
        if c == "-" or c.isdigit():
            return self.parse_number()
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        self.error("unexpected character %r" % c)

    def parse_object(self):
        obj = OrderedDict()
        self.i += 1
        while True:
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == "}":
                self.i += 1
                return obj
            key = self.parse_key()
            self.ws()
            if self.s[self.i] != ":":
                self.error("expected ':'")
            self.i += 1
            obj[key] = self.parse_value()
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1

    def parse_key(self):
        self.ws()
        if self.s[self.i] in "\"'":
            return self.parse_string()
        m = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", self.s[self.i:])
        if not m:
            self.error("bad object key")
        self.i += m.end()
        return m.group(0)

    def parse_array(self):
        arr = []
        self.i += 1
        while True:
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == "]":
                self.i += 1
                return arr
            # Tolerate elided elements (`[a, , b]`). JS treats these as
            # sparse-array holes; we skip them rather than fail the file.
            if self.s[self.i] == ",":
                self.i += 1
                continue
            arr.append(self.parse_value())
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1

    def parse_string(self):
        """
        Handles ', " and ` (template literal). Host data files use backticks
        for multi-line query content, including literal shell syntax such as
        ${IFS}, which is backslash-escaped in the source and unescapes to
        plain text here - matching what the browser sees.
        """
        quote = self.s[self.i]
        self.i += 1
        out = []
        esc = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
               '"': '"', "'": "'", "/": "/", "b": "\b", "f": "\f"}
        while self.i < len(self.s):
            c = self.s[self.i]
            if c == "\\":
                nxt = self.s[self.i + 1]
                if nxt == "u":
                    out.append(chr(int(self.s[self.i + 2:self.i + 6], 16)))
                    self.i += 6
                    continue
                out.append(esc.get(nxt, nxt))
                self.i += 2
                continue
            if c == quote:
                self.i += 1
                return "".join(out)
            out.append(c)
            self.i += 1
        self.error("unterminated string")

    def parse_number(self):
        m = re.match(r"-?\d+(\.\d+)?([eE][+-]?\d+)?", self.s[self.i:])
        self.i += m.end()
        t = m.group(0)
        return float(t) if ("." in t or "e" in t.lower()) else int(t)


def _load_const(path, name):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r"const\s+%s\s*=\s*" % name, text)
    if not m:
        raise ValueError("no `const %s =` in %s" % (name, path))
    p = JSParser(text)
    p.i = m.end()
    return p.parse_value()


def load_data_file(path):
    return _load_const(path, "DATA")


def load_actors(path):
    """Return {name-or-alias lowercased: (canonical, G-id)}."""
    if not os.path.exists(path):
        return {}
    try:
        actors = _load_const(path, "ACTORS")
    except ValueError:
        return {}
    index = {}
    for canonical, meta in actors.items():
        gid = meta.get("mitre")
        index[canonical.lower()] = (canonical, gid)
        for alias in meta.get("aliases") or []:
            index.setdefault(alias.lower(), (canonical, gid))
    return index


TACTIC_TAGS = {
    "TA0043": "reconnaissance", "TA0042": "resource-development",
    "TA0001": "initial-access", "TA0002": "execution",
    "TA0003": "persistence", "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion", "TA0006": "credential-access",
    "TA0007": "discovery", "TA0008": "lateral-movement",
    "TA0009": "collection", "TA0011": "command-and-control",
    "TA0010": "exfiltration", "TA0040": "impact",
}

FILE_TACTICS = {
    "recon": "TA0043", "initial_access": "TA0001", "discovery": "TA0007",
    "lateral": "TA0008", "lateral_movement": "TA0008",
    "credential": "TA0006", "credential_access": "TA0006",
    "collection": "TA0009", "c2": "TA0011", "exfil": "TA0010",
    "execution": "TA0002", "persistence": "TA0003",
    "privilege_escalation": "TA0004", "defense_evasion": "TA0005",
    "impact": "TA0040", "cloud": None,
}

# cloud.js is cross-tactic by design, so technique wins over file.
TECHNIQUE_TACTIC = {
    "T1078": "TA0005", "T1078.004": "TA0005",
    "T1098": "TA0003", "T1098.001": "TA0003", "T1098.003": "TA0003",
    "T1580": "TA0007", "T1526": "TA0007",
    "T1548": "TA0004", "T1548.005": "TA0004",
    "T1562": "TA0005", "T1562.008": "TA0005",
    "T1537": "TA0010", "T1496": "TA0040",
    "T1484": "TA0003", "T1484.002": "TA0003",
}

# Which row fields hold query logic, and how each maps to Sigma.
# Only `kibana` is translated into detection logic; the rest ride along as
# tonk metadata because they are not log-query formats.
QUERY_FIELDS = ("kibana", "arkime", "suricata", "sysmon", "powershell")


def infer_logsource(query, domain, tactic_file):
    """Best-effort Sigma logsource from the ECS field prefixes in the query."""
    q = query.lower()
    roots = set(re.findall(r"\b([a-z][a-z0-9_]*)\.[a-z]", q))

    if tactic_file == "cloud" or "aws.cloudtrail" in q or "event.provider" in q:
        if "azure" in q or "entra" in q or "azureactivedirectory" in q:
            return OrderedDict([("product", "azure"), ("service", "activitylogs")])
        if "googleapis" in q or "gcp." in q:
            return OrderedDict([("product", "gcp"), ("service", "gcp.audit")])
        return OrderedDict([("product", "aws"), ("service", "cloudtrail")])

    if domain == "host":
        if "registry" in roots:
            return OrderedDict([("category", "registry_set"), ("product", "windows")])
        if "dll" in roots:
            return OrderedDict([("category", "image_load"), ("product", "windows")])
        if "auditd" in roots:
            return OrderedDict([("product", "linux"), ("service", "auditd")])
        if "osquery" in roots:
            return OrderedDict([("product", "linux"), ("service", "osquery")])
        if "kubernetes" in roots or "container" in roots:
            return OrderedDict([("product", "kubernetes"), ("service", "audit")])
        if "process" in roots or "winlog" in roots:
            return OrderedDict([("category", "process_creation"), ("product", "windows")])
        if "file" in roots:
            return OrderedDict([("category", "file_event"), ("product", "windows")])
        return OrderedDict([("category", "process_creation"), ("product", "windows")])

    if "dns" in roots:
        return OrderedDict([("category", "dns"), ("product", "zeek")])
    if "tls" in roots or "ssl" in roots:
        return OrderedDict([("category", "network_connection"),
                            ("product", "zeek"), ("service", "ssl")])
    if "http" in roots or "url" in roots:
        return OrderedDict([("category", "proxy")])
    if "smb" in roots or "dcerpc" in roots:
        return OrderedDict([("category", "network_connection"),
                            ("product", "zeek"), ("service", "smb")])
    if "ldap" in roots:
        return OrderedDict([("category", "network_connection"),
                            ("product", "zeek"), ("service", "ldap")])
    if "kerberos" in roots:
        return OrderedDict([("category", "network_connection"),
                            ("product", "zeek"), ("service", "kerberos")])
    return OrderedDict([("category", "network_connection"), ("product", "zeek")])


def split_blocks(text):
    """
    Split a query field into independent labelled queries.

    Mirrors splitBlocks() in js/core.js so the exporter and the rendered
    site agree on what a single query is. Three comment roles:

      header       `// label` starting a block
      continuation a further `// line` before any query content
      annotation   `// note` AFTER query lines, explaining the clause above

    Returns [{label, query, annotations}, ...]; a single-query field comes
    back as one block.
    """
    if not text or not text.strip():
        return []
    blocks, cur, saw_blank = [], None, False
    for line in text.split("\n"):
        if re.match(r"^\s*//", line):
            t = re.sub(r"^\s*//\s?", "", line).strip()
            if cur and cur["query"].strip() and not saw_blank:
                cur["annotations"].append(t)
            elif cur and not cur["query"].strip():
                cur["label"] = (cur["label"] + " " + t).strip()
            else:
                cur = {"label": t, "query": "", "annotations": []}
                blocks.append(cur)
            saw_blank = False
            continue
        if not line.strip():
            saw_blank = True
            continue
        if cur is None:
            cur = {"label": "", "query": "", "annotations": []}
            blocks.append(cur)
        cur["query"] += ("\n" if cur["query"] else "") + line
        saw_blank = False
    return [b for b in blocks if b["query"].strip()]


AGG_PATTERNS = re.compile(
    r"aggregate|ratio_calc|stddev|std dev|sliding window|count per|unique |"
    r"baseline|alert when|flag when|last-seen|heartbeat|distinct|"
    r"per (principal|source|hour|user)", re.I)

PROSE_RE = re.compile(r"\[[^\]]{20,}\]", re.S)
INLINE_COMMENT_RE = re.compile(r"\s+//.*$", re.M)


def tokenize_clauses(block):
    """Split a KQL block into top-level AND-joined clauses."""
    clauses, depth, cur, i = [], 0, "", 0
    while i < len(block):
        c = block[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if depth == 0 and block[i:i + 5].upper() == " AND ":
            clauses.append(cur); cur = ""; i += 5; continue
        if depth == 0 and block[i:i + 4].upper() == "\nAND":
            clauses.append(cur); cur = ""; i += 4; continue
        cur += c
        i += 1
    if cur.strip():
        clauses.append(cur)

    out = []
    for cl in clauses:
        cl = cl.strip()
        if not cl:
            continue
        neg = False
        if re.match(r"^NOT\s+", cl, re.I):
            neg = True
            cl = re.sub(r"^NOT\s+", "", cl, flags=re.I)
        out.append((neg, cl.strip()))
    return out


def split_top_level(text, keyword):
    """
    Split on a keyword appearing outside any parentheses. Whitespace-tolerant,
    so both " OR " and a line-leading "OR " are recognised.
    """
    parts, depth, cur, i = [], 0, "", 0
    kw = keyword.upper()
    n = len(kw)
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if (depth == 0 and c in " \t\n"
                and text[i + 1:i + 1 + n].upper() == kw
                and (i + 1 + n >= len(text) or text[i + 1 + n] in " \t\n")):
            parts.append(cur)
            cur = ""
            i += 1 + n
            continue
        cur += c
        i += 1
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def parse_values(raw):
    """Parse the right-hand side of a KQL clause into Sigma values."""
    raw = raw.strip()
    if raw.startswith("(") and raw.endswith(")"):
        raw = raw[1:-1]
    vals = []
    for part in re.split(r"\bOR\b", raw, flags=re.I):
        p = part.strip().strip(",").strip()
        if not p:
            continue
        if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'":
            p = p[1:-1]
        vals.append(p)
    return vals


def wildcard_to_regex(value):
    """Convert a Sigma wildcard literal into an equivalent regex fragment."""
    out = []
    for ch in value:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def translate_block(block):
    """
    Translate one query block into a Sigma detection mapping.
    Returns (detection, condition, dropped).
    """
    dropped = []

    for p in PROSE_RE.findall(block):
        dropped.append("prose: " + re.sub(r"\s+", " ", p)[:120])
    block = PROSE_RE.sub(" ", block)
    block = INLINE_COMMENT_RE.sub("", block)
    # Splitting a field into blocks can leave a dangling leading conjunction,
    # e.g. an "alternative query" block authored to slot into the one above it.
    block = re.sub(r"^\s*(AND|OR)\s+", "", block, flags=re.I)

    # A block may be a top-level OR of groups, e.g.
    #   (a: 1 AND b: 2)
    #   OR c: 3
    # In Sigma each side becomes its own selection, OR-ed in the condition.
    or_parts = split_top_level(block, "OR")
    if len(or_parts) > 1:
        detection, conds, dropped_all = OrderedDict(), [], list(dropped)
        for i, part in enumerate(or_parts):
            part = part.strip()
            if part.startswith("(") and part.endswith(")"):
                part = part[1:-1].strip()
            sel, filt, drp = translate_and_group(part)
            dropped_all.extend(drp)
            if not sel and not filt:
                continue
            expr = []
            if sel:
                name = "selection_%d" % i
                detection[name] = sel
                expr.append(name)
            for j, f in enumerate(filt):
                fname = "filter_%d_%d" % (i, j)
                detection[fname] = f
                expr.append("not " + fname)
            if not expr:
                continue
            joined = " and ".join(expr)
            conds.append("(%s)" % joined if len(expr) > 1 else joined)
        if not conds:
            return None, None, dropped_all
        return detection, " or ".join(conds), dropped_all

    selection, filters, drp = translate_and_group(block)
    dropped.extend(drp)

    detection, parts = OrderedDict(), []
    if selection:
        detection["selection"] = selection
        parts.append("selection")
    for idx, f in enumerate(filters):
        detection["filter_%d" % idx] = f
        parts.append("not filter_%d" % idx)

    if not parts:
        return None, None, dropped
    return detection, " and ".join(parts), dropped


def translate_and_group(block):
    """Translate one AND-joined group into (selection, filters, dropped)."""
    dropped = []
    selection, filters = OrderedDict(), []

    for negated, clause in tokenize_clauses(block):
        clause = clause.strip().rstrip(",")
        if not clause:
            continue
        flat = clause.replace("\n", " ").strip()

        if AGG_PATTERNS.search(clause) and not re.match(r"^[\w.@\-]+\s*:", flat):
            dropped.append("aggregation: " + re.sub(r"\s+", " ", clause)[:120])
            continue

        m = re.match(r"^([\w.@\-]+)\s*(>=|<=|>|<)\s*([\d.]+)$", flat)
        if m:
            field, op, num = m.groups()
            mod = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}[op]
            selection["%s|%s" % (field, mod)] = int(float(num))
            dropped.append("numeric-comparison (%s %s %s): emitted as |%s "
                           "modifier, backend support varies" % (field, op, num, mod))
            continue

        m = re.match(r"^([\w.@\-]+)\s*:\s*\[\s*([\d.]+)\s+TO\s+([\d.]+)\s*\]$",
                     flat, re.I)
        if m:
            field, lo, hi = m.groups()
            selection["%s|gte" % field] = int(float(lo))
            selection["%s|lte" % field] = int(float(hi))
            dropped.append("range (%s %s TO %s): split into gte/lte modifiers"
                           % (field, lo, hi))
            continue

        m = re.match(r"^([\w.@\-]+)\s*:\s*(.+)$", clause, re.S)
        if not m:
            if clause.strip():
                dropped.append("unparsed: " + re.sub(r"\s+", " ", clause)[:120])
            continue

        field, rhs = m.group(1), m.group(2).strip()
        if re.match(r"^NOT\s+", rhs, re.I):
            negated = True
            rhs = re.sub(r"^NOT\s+", "", rhs, flags=re.I)

        # A value group may itself contain top-level ANDs, e.g.
        #   process.command_line: (*comsvcs* AND *MiniDump*)
        # In Sigma that is the |all modifier, not a single literal value.
        inner = rhs.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1].strip()
        and_parts = split_top_level(inner, "AND")

        if len(and_parts) > 1:
            positives, negatives = [], []
            for part in and_parts:
                if re.match(r"^NOT\s+", part, re.I):
                    negatives.append(re.sub(r"^NOT\s+", "", part, flags=re.I))
                else:
                    positives.append(part)
            for neg_val in negatives:
                nv = parse_values(neg_val)
                if nv:
                    filters.append(OrderedDict([
                        (field, nv[0] if len(nv) == 1 else nv)]))
            flat_pos = []
            for pv in positives:
                flat_pos.extend(parse_values(pv))
            if not flat_pos:
                dropped.append("empty-value: " + field)
                continue
            if len(flat_pos) > 1:
                key = field + "|all"
                payload = flat_pos
            else:
                key, payload = field, flat_pos[0]
            if negated:
                filters.append(OrderedDict([(key, payload)]))
            else:
                selection[key] = payload
            continue

        values = parse_values(rhs)
        if not values:
            dropped.append("empty-value: " + field)
            continue

        raw_vals, use_re = [], False
        for v in values:
            if len(v) > 2 and v.startswith("/") and v.endswith("/"):
                raw_vals.append((v[1:-1], True)); use_re = True
            else:
                raw_vals.append((v, False))

        if use_re:
            # Sigma cannot mix a regex list with wildcard literals, so promote
            # the wildcard values to equivalent regex.
            converted = []
            for val, was_re in raw_vals:
                candidate = val if was_re else wildcard_to_regex(val)
                try:
                    re.compile(candidate)
                except re.error as exc:
                    # Invalid regex in the source. Emitting it would produce a
                    # rule that fails to load, so quarantine it and say so.
                    dropped.append("invalid-regex on %s (%s): %r - left out of "
                                   "detection, see original_query"
                                   % (field, exc, candidate[:80]))
                    continue
                converted.append(candidate)
            if not converted:
                continue
            if len(raw_vals) > 1:
                dropped.append("mixed regex and wildcard values on %s: "
                               "wildcards promoted to regex, verify intent"
                               % field)
        else:
            converted = [v for v, _ in raw_vals]
        key = field + ("|re" if use_re else "")
        payload = converted[0] if len(converted) == 1 else converted

        if negated:
            filters.append(OrderedDict([(key, payload)]))
        elif key in selection:
            prev = selection[key]
            merged = prev if isinstance(prev, list) else [prev]
            merged += payload if isinstance(payload, list) else [payload]
            selection[key] = merged
        else:
            selection[key] = payload

    return selection, filters, dropped


TRIPWIRE_RE = re.compile(r"^\[OFF-NET TRIPWIRE\]\s*")
AIRGAP_NOTE_RE = re.compile(
    r"^\[AIR-GAP TRIPWIRE\].*?(?:thorough investigation\.|"
    r"priority-1 escalation[^.]*\.)\s*", re.S)


def extract_falsepositives(notes):
    if not notes:
        return ["Unknown - baseline before enabling"]
    m = re.search(r"(?:FALSE POSITIVES?|False positives?)\s*[:\-]\s*(.+?)"
                  r"(?:\.\s+[A-Z][a-z]|\Z)", notes, re.S)
    if m:
        return [re.sub(r"\s+", " ", m.group(1)).strip().rstrip(".")[:400]]
    if re.search(r"\bfalse positive", notes, re.I):
        for sent in re.split(r"(?<=\.)\s+", notes):
            if re.search(r"\bfalse positive", sent, re.I):
                return [re.sub(r"\s+", " ", sent).strip().rstrip(".")[:400]]
    return ["Unknown - baseline before enabling"]


def derive_level(indicator, notes):
    text = (indicator or "") + " " + (notes or "")
    if TRIPWIRE_RE.match(indicator or "") or "priority-1" in text.lower():
        return "high"
    if re.search(r"almost never benign|rare in a stable|treat as priority",
                 text, re.I):
        return "high"
    if re.search(r"high-confidence|high-signal|smoking-gun", text, re.I):
        return "high"
    if re.search(r"noisy|tunable|baseline before|lead, not", text, re.I):
        return "low"
    return "medium"


def actor_tags(row, actor_index):
    tags, seen = [], set()
    for bucket in ("apt", "malware", "activity"):
        for entry in row.get(bucket) or []:
            hit = actor_index.get((entry.get("name") or "").strip().lower())
            if hit and hit[1] and hit[1] not in seen:
                seen.add(hit[1])
                tags.append("attack." + hit[1].lower())
    return tags


def slugify(text, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return s[:maxlen].strip("_") or "rule"


def build_rules(row, tech, domain, source_file, actor_index, today):
    """Produce one Sigma rule per query block in a TONK indicator row."""
    rules = []
    indicator = TRIPWIRE_RE.sub("", row.get("indicator", "") or "").strip()
    notes = AIRGAP_NOTE_RE.sub("", row.get("notes", "") or "").strip()
    sub = row.get("sub", "") or tech.get("name", "")
    tech_id = tech.get("id", "")
    base = os.path.basename(source_file)[:-3]

    tactic = (TECHNIQUE_TACTIC.get(tech_id) or FILE_TACTICS.get(base)
              or TECHNIQUE_TACTIC.get(tech_id.split(".")[0]))

    tags = []
    if tactic and tactic in TACTIC_TAGS:
        tags.append("attack." + TACTIC_TAGS[tactic])
    for t in re.findall(r"T\d{4}(?:\.\d{3})?", tech_id + " " + sub):
        tag = "attack." + t.lower()
        if tag not in tags:
            tags.append(tag)
    tags += [t for t in actor_tags(row, actor_index) if t not in tags]

    refs = [c.strip() for c in (row.get("cite") or "").split(",") if c.strip()]

    blocks = split_blocks(row.get("kibana", "")) or [
        {"label": "", "query": "", "annotations": []}]
    multi = len(blocks) > 1

    for idx, blk in enumerate(blocks):
        query = blk["query"]
        if query.strip():
            detection, condition, dropped = translate_block(query)
        else:
            detection, condition, dropped = None, None, ["no KQL in source row"]

        fidelity = ("metadata" if detection is None
                    else "partial" if dropped else "full")

        title = sub if not multi else "%s (%s)" % (
            sub, blk["label"] or "query %d" % (idx + 1))
        title = re.sub(r"\s+", " ", title).strip()[:120]

        uid = str(uuid.uuid5(NS, "%s|%s|%s|%d" % (domain, tech_id, sub, idx)))

        desc = [indicator] if indicator else []
        if multi and blk["label"]:
            desc.append("Query block: %s." % blk["label"])
        for a in blk["annotations"]:
            desc.append(a if a.endswith(".") else a + ".")
        if fidelity == "metadata":
            desc.append("NOTE: no machine-translatable query logic (relies on "
                        "aggregation, statistical baselining, or an external "
                        "analytics layer). This rule is a documentation stub - "
                        "see the tonk section for the original hunt logic.")
        elif fidelity == "partial":
            desc.append("NOTE: partial conversion - one or more source clauses "
                        "could not be expressed in stock Sigma. See "
                        "tonk.dropped_clauses.")

        rule = OrderedDict()
        rule["title"] = title
        rule["id"] = uid
        rule["status"] = "experimental"
        rule["description"] = " ".join(desc).strip() or title
        if refs:
            rule["references"] = refs
        rule["author"] = AUTHOR
        rule["date"] = today
        if tags:
            rule["tags"] = tags
        rule["logsource"] = infer_logsource(query, domain, base)

        if detection:
            det = OrderedDict(detection)
            det["condition"] = condition
            rule["detection"] = det
        else:
            rule["detection"] = OrderedDict([
                ("selection", OrderedDict([("EventID|exists", True)])),
                ("condition", "selection and not selection"),
            ])

        rule["falsepositives"] = extract_falsepositives(notes)
        rule["level"] = derive_level(row.get("indicator", ""), notes)

        tonk = OrderedDict()
        tonk["fidelity"] = fidelity
        tonk["source_file"] = os.path.relpath(source_file, REPO)
        tonk["domain"] = domain
        tonk["technique"] = tech_id
        tonk["technique_name"] = tech.get("name", "")
        if row.get("os"):
            tonk["os"] = row["os"]
        if multi:
            tonk["query_block"] = "%d of %d" % (idx + 1, len(blocks))
        tonk["original_query"] = query or row.get("kibana", "")
        for extra in ("arkime", "suricata", "sysmon", "powershell",
                      "registry", "ossdetect", "tools"):
            if row.get(extra):
                tonk[extra] = row[extra]
        variables = sorted(set(re.findall(r"\$[A-Z_][A-Z0-9_]*", query or "")))
        if variables:
            tonk["requires_variables"] = variables
        if dropped:
            tonk["dropped_clauses"] = dropped
        actors = [a.get("name") for a in (row.get("apt") or []) if a.get("name")]
        if actors:
            tonk["actors"] = actors
        if notes:
            tonk["analyst_notes"] = notes
        rule["tonk"] = tonk

        fname = "%s_%s.yml" % (tech_id.lower().replace(".", "_"),
                               slugify(title.replace(tech_id, "")))
        rules.append((fname, rule, fidelity))

    return rules


NEEDS_QUOTE = re.compile(
    r"^[\s>|*&!%@`{\[\]}#,'\"]|[:#]\s|\s$|^$|^[-?]\s"
    r"|^(true|false|null|yes|no|on|off|~)$", re.I)


def yaml_scalar(v, indent):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if v is None:
        return "null"
    s = str(v)
    # YAML forbids raw control characters. Source data legitimately contains
    # some (e.g. the ZIP magic bytes PK\x03\x04), so escape rather than drop.
    if any(ord(ch) < 32 and ch not in "\n\t" for ch in s):
        s = "".join(ch if (ord(ch) >= 32 or ch in "\n\t")
                    else "\\x%02x" % ord(ch) for ch in s)
    if "\n" in s:
        pad = " " * (indent + 4)
        body = "\n".join((pad + ln) if ln.strip() else ""
                         for ln in s.split("\n"))
        return "|-\n" + body.rstrip()
    if NEEDS_QUOTE.search(s) or s != s.strip():
        return "'" + s.replace("'", "''") + "'"
    return s


KEY_NEEDS_QUOTE = re.compile(r"^[@`\-?:,\[\]{}#&*!|>'\"%]|:\s|^$")


def yaml_key(k):
    """Quote keys YAML cannot parse bare, such as ECS's @timestamp."""
    k = str(k)
    return "'" + k.replace("'", "''") + "'" if KEY_NEEDS_QUOTE.search(k) else k


def to_yaml(obj, indent=0):
    out, pad = [], " " * indent
    for k, v in obj.items():
        k = yaml_key(k)
        if isinstance(v, dict):
            out.append("%s%s:" % (pad, k))
            nested = to_yaml(v, indent + 4)
            if nested:
                out.append(nested)
        elif isinstance(v, list):
            if not v:
                out.append("%s%s: []" % (pad, k))
                continue
            out.append("%s%s:" % (pad, k))
            for item in v:
                if isinstance(item, dict):
                    first = True
                    for ik, iv in item.items():
                        prefix = ("%s    - " % pad) if first else ("%s      " % pad)
                        out.append("%s%s: %s" % (prefix, ik,
                                                 yaml_scalar(iv, indent + 6)))
                        first = False
                else:
                    out.append("%s    - %s" % (pad, yaml_scalar(item, indent + 4)))
        else:
            out.append("%s%s: %s" % (pad, k, yaml_scalar(v, indent)))
    return "\n".join(out)


def collect(repo):
    actor_index = load_actors(os.path.join(repo, "net", "js", "actors.js"))
    today = date.today().strftime("%Y/%m/%d")
    results = []
    for domain in ("net", "host"):
        ddir = os.path.join(repo, domain, "js", "data")
        if not os.path.isdir(ddir):
            continue
        for fname in sorted(os.listdir(ddir)):
            if not fname.endswith(".js"):
                continue
            path = os.path.join(ddir, fname)
            try:
                data = load_data_file(path)
            except Exception as exc:
                print("  ! parse failed %s: %s" % (fname, exc), file=sys.stderr)
                continue
            for tech in data:
                for row in tech.get("rows", []):
                    for item in build_rules(row, tech, domain, path,
                                            actor_index, today):
                        results.append((domain, fname[:-3], item))
    return results


def write_out(results, outdir):
    # Regenerate from scratch; otherwise a re-run collides with the previous
    # output and silently accumulates _1/_2 duplicates.
    rules_root = os.path.join(outdir, "rules")
    if os.path.isdir(rules_root):
        shutil.rmtree(rules_root)
    counts, index, used = Counter(), [], set()
    for domain, tactic, (fname, rule, fidelity) in results:
        tdir = os.path.join(outdir, "rules", domain, tactic)
        os.makedirs(tdir, exist_ok=True)
        path, n = os.path.join(tdir, fname), 1
        while path in used or os.path.exists(path):
            path = os.path.join(tdir, "%s_%d.yml" % (fname[:-4], n))
            n += 1
        used.add(path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Generated by TONK sigma-export.py - do not edit by hand.\n")
            fh.write("# Source of truth: %s\n" % rule["tonk"]["source_file"])
            fh.write(to_yaml(rule) + "\n")
        counts[fidelity] += 1
        counts["total"] += 1
        index.append({"file": os.path.relpath(path, outdir), "id": rule["id"],
                      "title": rule["title"],
                      "technique": rule["tonk"]["technique"],
                      "domain": domain, "tactic": tactic,
                      "fidelity": fidelity, "level": rule["level"]})
    with open(os.path.join(outdir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
    return counts, index


def write_report(outdir, counts, index):
    by_domain = Counter((i["domain"], i["fidelity"]) for i in index)
    by_tactic = Counter(i["tactic"] for i in index)
    by_level = Counter(i["level"] for i in index)
    partials = [i for i in index if i["fidelity"] == "partial"]
    stubs = [i for i in index if i["fidelity"] == "metadata"]
    total = counts["total"] or 1

    L = ["# TONK to Sigma - Conversion Report", "",
         "Generated by `.tools/sigma-export.py`. Every rule carries a fidelity",
         "grade, so nothing is lost silently in translation.", "",
         "## Totals", "", "| Fidelity | Rules | Share |", "| --- | ---: | ---: |"]
    for g in ("full", "partial", "metadata"):
        L.append("| %s | %d | %.1f%% |" % (g, counts[g], 100.0 * counts[g] / total))
    L += ["| **total** | **%d** | |" % counts["total"], ""]

    L += ["## By domain", "", "| Domain | full | partial | metadata |",
          "| --- | ---: | ---: | ---: |"]
    for d in ("net", "host"):
        L.append("| %s | %d | %d | %d |" % (d, by_domain[(d, "full")],
                                            by_domain[(d, "partial")],
                                            by_domain[(d, "metadata")]))
    L += ["", "## By severity", "", "| Level | Rules |", "| --- | ---: |"]
    for lv in ("high", "medium", "low"):
        L.append("| %s | %d |" % (lv, by_level[lv]))
    L += ["", "## By source file", "", "| Tactic file | Rules |", "| --- | ---: |"]
    for t, n in sorted(by_tactic.items(), key=lambda x: -x[1]):
        L.append("| %s | %d |" % (t, n))

    L += ["", "## What the grades mean", "",
          "- **full** - every clause in the source query translated cleanly.",
          "  Still requires `$VARIABLE` substitution and field-mapping",
          "  validation against your own index before use.",
          "- **partial** - translated, but at least one clause was approximated",
          "  or dropped. Causes: aggregation and statistical logic (Sigma cannot",
          "  express windowed counts without backend correlation rules), numeric",
          "  comparison modifiers with uneven backend support, `[A TO B]` ranges",
          "  split into gte/lte, and inline analyst prose. Each rule lists its",
          "  own reasons under `tonk.dropped_clauses`.",
          "- **metadata** - no machine-translatable logic. The rule is an inert",
          "  documentation stub carrying the original hunt logic, Arkime and",
          "  Suricata syntax, and analyst notes under `tonk`. These are the",
          "  indicators that genuinely need an analytics layer (Zeek plus RITA,",
          "  SIEM aggregation) rather than a signature.", "",
          "## Known limitations", "",
          "- Rules are **not** validated against a live index. Field names",
          "  assume ECS normalisation; confirm against your own mappings first.",
          "- `logsource` is inferred from field prefixes. It is a starting",
          "  point, not an assertion about your pipeline.",
          "- Thresholds carried from source notes need environment baselining.",
          "- The `tonk:` key is a non-standard extension. Stock Sigma tooling",
          "  ignores unknown top-level keys; strict validators may warn.", ""]

    if partials:
        L += ["## Partial conversions (first 25)", ""]
        L += ["- `%s` - %s" % (i["technique"], i["title"]) for i in partials[:25]]
        L.append("")
    if stubs:
        L += ["## Documentation stubs (first 25)", ""]
        L += ["- `%s` - %s" % (i["technique"], i["title"]) for i in stubs[:25]]
        L.append("")

    with open(os.path.join(outdir, "CONVERSION_REPORT.md"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(L))


def validate(outdir):
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        print("\npySigma not installed - skipping validation "
              "(pip install pysigma)")
        return None
    ok, failed = 0, []
    for root, _d, files in os.walk(os.path.join(outdir, "rules")):
        for f in sorted(files):
            if not f.endswith(".yml"):
                continue
            path = os.path.join(root, f)
            try:
                with open(path, encoding="utf-8") as fh:
                    SigmaCollection.from_yaml(fh.read())
                ok += 1
            except Exception as exc:
                failed.append((os.path.relpath(path, outdir), str(exc)[:160]))
    print("\npySigma validation: %d parsed, %d failed" % (ok, len(failed)))
    for p, e in failed[:12]:
        print("  FAIL %s\n       %s" % (p, e))
    return ok, failed


def main():
    ap = argparse.ArgumentParser(
        description="Export TONK indicators as a Sigma ruleset.")
    ap.add_argument("--out", default=os.path.join(REPO, "sigma"))
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    print("TONK -> Sigma exporter\nrepo: %s" % REPO)
    results = collect(REPO)
    print("built %d rules" % len(results))

    if args.stats:
        c = Counter(r[2] for _d, _t, r in results)
        for k in ("full", "partial", "metadata"):
            print("  %-9s %d" % (k, c[k]))
        return

    os.makedirs(args.out, exist_ok=True)
    counts, index = write_out(results, args.out)
    write_report(args.out, counts, index)
    print("\nwrote %d rules to %s" % (counts["total"], args.out))
    for k in ("full", "partial", "metadata"):
        print("  %-9s %d" % (k, counts[k]))
    print("  report   %s/CONVERSION_REPORT.md" % args.out)
    print("  index    %s/index.json" % args.out)
    if args.validate:
        validate(args.out)


if __name__ == "__main__":
    main()
