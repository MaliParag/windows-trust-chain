#!/usr/bin/env python3
"""Bake audio read-along into a rendered mdBook chapter page (in place).

Reuses the real rendered page (formatting, citations, diagrams, math intact) and:
  * wraps narrated PROSE words in <span class="ra-w" data-s="..."> for
    highlighting (skips code/pre/tables/figures/KaTeX math and leaves citation
    markers like [66] as plain text),
  * aligns compact narration timings (reader-timing/<key>.json) to the rendered
    prose via difflib, interpolating over gaps,
  * injects a fixed audio player bar + highlight/scroll/seek JS + CSS, with the
    MP3 served from the public release (AUDIO_BASE env).

Usage: inject_readalong.py <book_html> <key> [<out_html>]
Env:   AUDIO_BASE (default: the audio-v1 release download URL)
"""
import os, re, sys, json, html
from html.parser import HTMLParser
from difflib import SequenceMatcher

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMING_DIR = os.path.join(REPO, "reader-timing")
AUDIO_BASE = os.environ.get(
    "AUDIO_BASE",
    "https://github.com/MaliParag/windows-trust-chain/releases/download/audio-v1")

SKIP_TAGS = {"pre", "code", "table", "figure", "svg", "script", "style",
             "figcaption", "math", "annotation"}
VOID = {"img", "br", "hr", "input", "meta", "link", "col", "source", "area"}
CITE_RE = re.compile(r"^\[\d+(?:\s*,\s*\d+)*\]$")
NORM_RE = re.compile(r"[^a-z0-9]")


def norm(tok):
    return NORM_RE.sub("", tok.lower())


class ProseWrapper(HTMLParser):
    """Re-emit an HTML fragment, wrapping prose words in spans (outside skip
    contexts: SKIP_TAGS or any element whose class contains 'katex')."""
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.out = []
        self.stack = []       # bool per open element: does it trigger skip
        self.skip_depth = 0
        self._spans = []      # {tok, ph}

    def _attrs(self, attrs):
        return "".join(f' {k}="{html.escape(v, quote=True)}"' if v is not None
                       else f" {k}" for k, v in attrs)

    def handle_starttag(self, tag, attrs):
        self.out.append(f"<{tag}{self._attrs(attrs)}>")
        if tag in VOID:
            return
        cls = dict(attrs).get("class") or ""
        trig = tag in SKIP_TAGS or "katex" in cls
        self.stack.append(trig)
        if trig:
            self.skip_depth += 1

    def handle_startendtag(self, tag, attrs):
        self.out.append(f"<{tag}{self._attrs(attrs)}/>")

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if self.stack:
            if self.stack.pop():
                self.skip_depth -= 1
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self.skip_depth > 0 or not data.strip():
            self.out.append(data)
            return
        for piece in re.split(r"(\s+)", data):
            if not piece:
                continue
            if piece.isspace():
                self.out.append(piece)
                continue
            if CITE_RE.match(piece) or not norm(piece):
                self.out.append(piece)
                continue
            self._spans.append({"tok": piece, "ph": len(self.out)})
            self.out.append(None)

    def handle_entityref(self, name):
        self.out.append(f"&{name};")

    def handle_charref(self, name):
        self.out.append(f"&#{name};")

    def handle_comment(self, data):
        self.out.append(f"<!--{data}-->")

    def handle_decl(self, decl):
        self.out.append(f"<!{decl}>")


def align_timings(prose_toks, narr):
    a = [norm(t) for t in prose_toks]
    b = [norm(w) for w, _ in narr]
    starts = [None] * len(prose_toks)
    for i, j, k in SequenceMatcher(a=a, b=b, autojunk=False).get_matching_blocks():
        for d in range(k):
            starts[i + d] = narr[j + d][1]
    known = [(i, s) for i, s in enumerate(starts) if s is not None]
    if not known:
        return [0.0] * len(prose_toks)
    for i in range(known[0][0]):
        starts[i] = known[0][1]
    for i in range(known[-1][0] + 1, len(starts)):
        starts[i] = known[-1][1]
    for (i0, s0), (i1, s1) in zip(known, known[1:]):
        for k in range(i0 + 1, i1):
            starts[k] = round(s0 + (s1 - s0) * (k - i0) / (i1 - i0), 3)
    return [round(s, 3) for s in starts]


CSS = """<style id="ra-css">
#ra-toggle{position:fixed;right:14px;bottom:14px;z-index:10000;border:0;
 border-radius:22px;padding:10px 16px;background:#3b6fb0;color:#fff;cursor:pointer;
 font:600 .9rem/1 -apple-system,Segoe UI,Roboto,sans-serif;box-shadow:0 2px 10px #0005}
#ra-bar{position:fixed;left:0;right:0;bottom:0;z-index:9999;display:none;
 gap:14px;align-items:center;padding:8px 16px;background:var(--bg,#1b1b1f);
 border-top:1px solid #8884;box-shadow:0 -2px 12px #0004;flex-wrap:wrap}
#ra-bar.on{display:flex} body.ra-on #ra-toggle{display:none}
#ra-bar audio{height:34px;max-width:100%} #ra-close{margin-left:auto;
 background:none;border:0;color:inherit;font-size:1.2rem;cursor:pointer;opacity:.7}
#ra-bar label{font-size:.85rem;opacity:.8;display:flex;gap:5px;align-items:center}
.ra-w{border-radius:4px;cursor:pointer;scroll-margin:45vh}
.ra-w.ra-active{background:#3b6fb0;color:#fff}
body.ra-on main{padding-bottom:96px}
</style>"""


def build_bar(audio_url):
    return f"""<button id="ra-toggle" title="Listen with read-along">\U0001F3A7 Read-along</button>
<div id="ra-bar">
  <audio id="ra-audio" controls preload="none" src="{audio_url}"></audio>
  <label>Speed <select id="ra-speed"><option>0.75</option><option selected>1</option>
    <option>1.1</option><option>1.25</option><option>1.5</option></select></label>
  <label><input type="checkbox" id="ra-follow" checked> Follow</label>
  <button id="ra-close" title="Hide">\u2715</button>
</div>"""


JS = """<script id="ra-js">
(function(){
 var spans=[].slice.call(document.querySelectorAll('.ra-w[data-s]'));
 var bar=document.getElementById('ra-bar'),tgl=document.getElementById('ra-toggle'),
 A=document.getElementById('ra-audio'),cl=document.getElementById('ra-close'),
 follow=document.getElementById('ra-follow'),speed=document.getElementById('ra-speed');
 if(!spans.length||!A) return;
 var starts=spans.map(function(s){return parseFloat(s.dataset.s)}),cur=-1;
 function open(){bar.classList.add('on');document.body.classList.add('ra-on');}
 tgl.addEventListener('click',function(){open();A.play();});
 cl.addEventListener('click',function(){bar.classList.remove('on');
   document.body.classList.remove('ra-on');A.pause();});
 function find(t){var lo=0,hi=starts.length-1,a=-1;while(lo<=hi){var m=(lo+hi)>>1;
   if(starts[m]<=t){a=m;lo=m+1}else hi=m-1}return a}
 function tick(){var i=find(A.currentTime);
   if(i!==cur&&i>=0){if(cur>=0)spans[cur].classList.remove('ra-active');
     var el=spans[i];el.classList.add('ra-active');
     if(follow.checked){var r=el.getBoundingClientRect();
       if(r.top<70||r.bottom>innerHeight-110)el.scrollIntoView({block:'center',behavior:'smooth'});}
     cur=i;}
   if(!A.paused&&!A.ended)requestAnimationFrame(tick);}
 A.addEventListener('play',function(){open();requestAnimationFrame(tick);});
 A.addEventListener('seeked',tick);
 spans.forEach(function(s,i){s.addEventListener('click',function(){
   if(!bar.classList.contains('on'))open();A.currentTime=starts[i]+0.001;A.play();});});
 speed.addEventListener('change',function(){A.playbackRate=parseFloat(speed.value)});
})();
</script>"""


def main():
    book_html = sys.argv[1]
    key = sys.argv[2]
    out_html = sys.argv[3] if len(sys.argv) > 3 else book_html

    tf = os.path.join(TIMING_DIR, key + ".json")
    if not os.path.exists(tf):
        print(f"skip {key}: no timing"); return
    t = json.load(open(tf))
    narr = list(zip(t["w"], t["s"]))

    page = open(book_html, encoding="utf-8").read()
    m = re.search(r"<main\b[^>]*>(.*?)</main>", page, re.S)
    if not m:
        print(f"skip {key}: no <main>"); return

    w = ProseWrapper()
    w.feed(m.group(1))
    toks = [s["tok"] for s in w._spans]
    starts = align_timings(toks, narr)
    for s, st in zip(w._spans, starts):
        w.out[s["ph"]] = f'<span class="ra-w" data-s="{st}">{html.escape(s["tok"])}</span>'
    new_frag = "".join(x for x in w.out if x is not None)

    page = page[:m.start(1)] + new_frag + page[m.end(1):]
    inject = CSS + build_bar(f"{AUDIO_BASE}/{key}.mp3") + JS
    page = page.replace("</body>", inject + "\n</body>", 1)
    open(out_html, "w", encoding="utf-8").write(page)
    print(f"{key}: {len(toks)} prose words baked")


if __name__ == "__main__":
    main()
