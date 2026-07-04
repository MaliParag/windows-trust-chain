#!/usr/bin/env python3
"""LOCAL step: produce compact narration timing for the read-along.

Reads the full timing built earlier (~/audiobook-wtc/reader/data/<key>.json) and
writes a compact {"w":[...words...],"s":[...starts...]} per chapter into
reader-timing/ in this repo. Only the compact output is committed; CI uses it to
align + bake the read-along into the built pages.
"""
import os, json, glob

SRC = os.path.expanduser("~/audiobook-wtc/reader/data")
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "reader-timing")
os.makedirs(OUT, exist_ok=True)

n = 0
for f in sorted(glob.glob(os.path.join(SRC, "*.json"))):
    key = os.path.basename(f)[:-5]
    if key == "index":
        continue
    data = json.load(open(f))
    words, starts = [], []
    for p in data["paragraphs"]:
        for w in p["words"]:
            words.append(w["w"])
            starts.append(round(w["s"], 2))
    json.dump({"title": data["title"], "w": words, "s": starts},
              open(os.path.join(OUT, key + ".json"), "w"),
              separators=(",", ":"))
    n += 1
print(f"wrote {n} compact timing files to reader-timing/")
