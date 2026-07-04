#!/usr/bin/env python3
"""Bake read-along into every built chapter page that has timing data.
Runs after `mdbook build`, over book/. Matches pages to timing keys by slug
(name minus number prefix). Intended for the CI deploy step (and local testing).
"""
import os, re, sys, glob, json, subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOOK = os.path.join(REPO, "book")
TIMING = os.path.join(REPO, "reader-timing")
INJECT = os.path.join(REPO, "tools", "inject_readalong.py")


def slug(name):
    return re.sub(r"^\d+[a-z]?-", "", name)


keys = {}
for f in glob.glob(os.path.join(TIMING, "*.json")):
    k = os.path.basename(f)[:-5]
    keys[slug(k)] = k

done = 0
for sub in ("front-matter", "chapters", "back-matter"):
    for page in sorted(glob.glob(os.path.join(BOOK, sub, "*.html"))):
        base = os.path.basename(page)[:-5]
        s = slug(base)
        if s in keys:
            subprocess.run([sys.executable, INJECT, page, keys[s]], check=True)
            done += 1

print(f"read-along baked into {done} pages")
