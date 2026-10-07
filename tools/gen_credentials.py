#!/usr/bin/env python3
"""Write memo's credential rules from two pinned, MIT-licensed rule sets.

  tools/gen_credentials.py            fetch the sources, rewrite memo's block
  tools/gen_credentials.py --check    exit 1 if memo's block is out of date
  tools/gen_credentials.py --sources DIR   read the files from DIR, offline

To update: change a pin below, run the script, and read the diff. A changed
file under an unchanged pin is refused, so the hashes change with the pins
(the refusal prints the new hash).

Kept: betterleaks rules marked "high" confidence that do not hang on an
assignment (`foo_key = ...` -- those are the noisy ones), and every pattern of
Microsoft's high-confidence set. Go's RE2 syntax is rewritten for Python's re.
A betterleaks rule whose filter reads anything but the secret's entropy and
regexes is dropped -- except `tokenRatio`, a word-likeness test we cannot
run: its term is left out, so the rule refuses a little more, never less.
A rule betterleaks reports only beside another (`components`) stands alone
here: one line of memory never holds the pair, and either half is a secret.
Needs Python 3.11+ (tomllib); memo itself does not.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
import urllib.request

HERE = os.path.dirname(os.path.realpath(__file__))
MEMO = os.path.join(HERE, os.pardir, "memo")

BETTERLEAKS = dict(
    name="betterleaks", tag="v1.9.0", file="betterleaks.toml",
    url="https://raw.githubusercontent.com/betterleaks/betterleaks/"
        "{tag}/config/{file}",
    sha256="a8f553eb634ac3c5c1ca3f0dc95e2b8abdea7d14b622604c5af07f30ce7926ef",
    home="https://github.com/betterleaks/betterleaks",
    copyright="Copyright (c) 2026 Zachary Rice")
# The repository has no release tags: pin the last commit to change the file.
MICROSOFT = dict(
    name="microsoft/security-utilities",
    tag="a5a4f54b91fc1096e16f47323ad8de27468d452f",
    file="HighConfidenceSecurityModels.json",
    url="https://raw.githubusercontent.com/microsoft/security-utilities/"
        "{tag}/GeneratedRegexPatterns/{file}",
    sha256="c516d3682d354f8f085b64bf9ca81f6d726b94446175b54ae265e0a9f56506f8",
    home="https://github.com/microsoft/security-utilities",
    copyright="Copyright (c) Microsoft Corporation.")

BEGIN, END = "# BEGIN GENERATED", "# END GENERATED"


def fetch(src, sources):
    if sources:
        with open(os.path.join(sources, src["file"]), "rb") as f:
            data = f.read()
    else:
        url = src["url"].format(**src)
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
    got = hashlib.sha256(data).hexdigest()
    if got != src["sha256"]:
        sys.exit("%s %s: sha256 is %s, pinned %s. If the pin moved on "
                 "purpose, update the hash." % (src["name"], src["file"], got,
                                                 src["sha256"]))
    return data


# ------------------------------------------------------- RE2 -> Python re

POSIX = {"alnum": "a-zA-Z0-9", "alpha": "a-zA-Z", "digit": "0-9",
         "lower": "a-z", "upper": "A-Z", "xdigit": "0-9a-fA-F",
         "space": r"\s", "word": r"\w"}


def scope_flags(p):
    """RE2 takes `(?i)` anywhere, to the end of the group; Python only at the
    very start. Rewrite `a(?i)b)` as `a(?i:b))`."""
    out, close, i = [], [0], 0
    while i < len(p):
        c = p[i]
        if c == "\\":
            out.append(p[i:i + 2])
            i += 2
            continue
        if c == "[":
            j = i + 1
            if p[j:j + 1] == "^":
                j += 1
            if p[j:j + 1] == "]":
                j += 1
            while p[j] != "]":
                if p[j] == "\\":
                    j += 1
                elif p.startswith("[:", j):
                    j = p.index(":]", j) + 1
                j += 1
            out.append(p[i:j + 1])
            i = j + 1
            continue
        m = re.match(r"\(\?([a-z]+)\)", p[i:])
        if m and out:
            out.append("(?%s:" % m.group(1))
            close[-1] += 1
            i += m.end()
            continue
        if c == "(":
            close.append(0)
        elif c == ")":
            out.append(")" * close.pop())
        out.append(c)
        i += 1
    return "".join(out) + ")" * close.pop()


RUNS = {"abcdefghijklmnopqrstuvwxyz": "a-z", "abcdef": "a-f",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ": "A-Z", "ABCDEF": "A-F",
        "0123456789": "0-9", "1234567890": "0-9"}


def ranges(p):
    """Microsoft spells out `[abc...xyzABC...XYZ1234567890]`: write it as
    `[a-zA-Z0-9]`, and check that each class still holds the same set."""
    out, i = [], 0
    while i < len(p):
        if p[i] == "\\":
            out.append(p[i:i + 2])
            i += 2
            continue
        if p[i] != "[":
            out.append(p[i])
            i += 1
            continue
        j = i + 1 + (p[i + 1] == "^")
        j += p[j] == "]"  # a ] first is a literal, not the end
        while p[j] != "]":
            j += 2 if p[j] == "\\" else 1
        old = body = p[i + 1:j]
        for run, short in RUNS.items():
            k = body.find(run)
            if k > 0 and body[k - 1] in "-\\":
                continue
            if k >= 0:
                body = body[:k] + short + body[k + len(run):]
        a, b = re.compile("[%s]" % old), re.compile("[%s]" % body)
        assert all(bool(a.match(chr(c))) == bool(b.match(chr(c)))
                   for c in range(128)), (old, body)
        out.append("[" + body + "]")
        i = j + 1
    return "".join(out)


def python_re(p):
    p = re.sub(r"\[:(\w+):\]", lambda m: POSIX[m.group(1)], p)
    p = p.replace(r"\z", r"\Z")
    p = ranges(scope_flags(p))
    re.compile(p, re.ASCII)  # RE2's \w \d \s \b are ASCII
    return p


# -------------------------------------------------- betterleaks filters

def split_or(s):
    """Top-level `||` terms of a CEL expression."""
    terms, depth, quote, start, i = [], 0, None, 0, 0
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote != "`":
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif s.startswith("||", i) and not depth:
            terms.append(s[start:i].strip())
            start = i + 2
            i += 1
        i += 1
    terms.append(s[start:].strip())
    return [t for t in terms if t]


def cel_strings(s):
    """The string literals of a CEL list: `raw` or "escaped"."""
    out = []
    for m in re.finditer(r'`([^`]*)`|"((?:[^"\\]|\\.)*)"', s):
        out.append(m.group(1) if m.group(1) is not None
                   else json.loads('"%s"' % m.group(2)))
    return out


SECRET = r'finding\["secret"\]'


def parse_filter(text):
    """(entropy, drop, keep) from a filter, or None if it reads anything we
    cannot. entropy is ">N" or ">=N": what the secret's must be, in bits
    per character."""
    entropy, drop, keep = "", [], []
    text = re.sub(r"\s+", " ", text.strip())
    while text.startswith("(") and len(split_or(text[1:-1])) > 1 \
            and text.endswith(")"):
        text = text[1:-1]
    for t in split_or(text):
        t = re.sub(r"\bfilter\.", "", t)
        m = re.fullmatch(r"entropy\(%s\) (<=?) ([\d.]+)" % SECRET, t)
        if m:
            entropy = (">" if m.group(1) == "<=" else ">=") + m.group(2)
            continue
        if re.fullmatch(r"tokenRatio\(%s\) >= [\d.]+" % SECRET, t):
            continue
        if re.fullmatch(r'matchesAny\(attributes\["path"\], \[.*\]\)', t):
            continue  # a file path: memory has none
        m = re.fullmatch(r"(!?)matchesAny\(%s, (\[.*\])\)" % SECRET, t)
        if m:
            xs = [python_re(x) for x in cel_strings(m.group(2))]
            if m.group(1):
                keep.append("|".join("(?:%s)" % x for x in xs))
            else:
                drop.extend(xs)
            continue
        m = re.fullmatch(r"containsAny\(%s, (\[.*\])\)" % SECRET, t)
        if m:
            drop.extend(re.escape(x) for x in cel_strings(m.group(1)))
            continue
        return None
    return entropy, drop, keep


def betterleaks(data):
    cfg = tomllib.loads(data.decode())
    stop = parse_filter(cfg.get("filter", ""))
    assert stop and not stop[0] and not stop[2], "global filter changed shape"
    rules, dropped = [], []
    for r in cfg["rules"]:
        if (r.get("confidence") != "high" or "regex" not in r
                or r.get("path") or r.get("skipReport")):
            continue
        if r["regex"].startswith(r"(?i)[\w.-]{0,50}?") \
                or "(?:=|>|:{1,3}=" in r["regex"]:
            continue  # a value after `name =`: the noisy, generic kind
        f = parse_filter(r.get("filter", ""))
        if f is None:
            dropped.append(r["id"])
            continue
        rules.append((r["id"], sorted({k.lower() for k in r["keywords"]}),
                      python_re(r["regex"]), r.get("secretGroup", 0)) + f)
    return rules, stop[1], dropped


def microsoft(data):
    rules = []
    for x in json.loads(data):
        rules.append(("%s %s" % (x["Id"], x["Name"]),
                      sorted({s.lower() for s in x["Signatures"]}),
                      python_re(x["Pattern"]), "refine", "", [], []))
    return rules


# ------------------------------------------------------------- output

def lit(s):
    if isinstance(s, str):
        for q in ("'", '"'):
            if q not in s and not s.endswith("\\") and "\n" not in s:
                return "r" + q + s + q
    return repr(s)


def tup(xs):
    xs = [lit(x) for x in xs]
    return "(%s,)" % xs[0] if len(xs) == 1 else "(%s)" % ", ".join(xs)


def block(bl, ms):
    rules, stop, dropped = bl
    out = [BEGIN + " by tools/gen_credentials.py: edit that, not this.",
           "# From %s %s, %s" % (BETTERLEAKS["name"], BETTERLEAKS["tag"],
                                 BETTERLEAKS["file"]),
           "#   %s, MIT License, %s" % (BETTERLEAKS["home"],
                                       BETTERLEAKS["copyright"]),
           "# and %s %s," % (MICROSOFT["name"], MICROSOFT["tag"][:12]),
           "#   GeneratedRegexPatterns/%s" % MICROSOFT["file"],
           "#   %s, MIT License, %s" % (MICROSOFT["home"],
                                       MICROSOFT["copyright"]),
           "# A rule: (keywords, regex, the secret's group, its entropy,",
           "# drop it if it matches any of these, keep it only if it matches "
           "all of these)",
           "CREDENTIAL_IGNORE = %s" % tup(stop),
           "CREDENTIAL_RULES = ("]
    for rid, kw, rx, grp, ent, drop, keep in rules + ms:
        out.append("    # " + rid)
        out.append("    (%s, %s, %s, %s, %s, %s)," % (
            tup(kw), lit(rx), lit(grp), lit(ent), tup(drop), tup(keep)))
    out.append(")")
    out.append(END)
    return "\n".join(out) + "\n", dropped


def splice(text, new):
    a, b = text.find(BEGIN), text.find(END)
    if a < 0 or b < a:
        sys.exit("memo has no %s ... %s block." % (BEGIN, END))
    return text[:a] + new + text[text.index("\n", b) + 1:]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if memo's block differs from the sources")
    ap.add_argument("--sources", metavar="DIR",
                    help="read %s and %s from DIR instead of the network"
                    % (BETTERLEAKS["file"], MICROSOFT["file"]))
    a = ap.parse_args()
    new, dropped = block(betterleaks(fetch(BETTERLEAKS, a.sources)),
                         microsoft(fetch(MICROSOFT, a.sources)))
    with open(MEMO, encoding="utf-8", newline="") as f:
        old = f.read()
    text = splice(old, new)
    if a.check:
        if text != old:
            sys.exit("memo's credential rules are out of date: run "
                     "tools/gen_credentials.py")
        print("memo's credential rules are current.")
        return
    if dropped:
        print("dropped, filter not understood: " + ", ".join(dropped),
              file=sys.stderr)
    if text != old:
        with open(MEMO, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    print("%d rules written." % new.count("\n    # "))


if __name__ == "__main__":
    main()
