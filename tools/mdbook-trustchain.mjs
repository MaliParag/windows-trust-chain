#!/usr/bin/env node
/**
 * mdBook preprocessor for "The Windows Trust Chain".
 *
 * The book's Markdown is authored for a Pandoc+Typst print pipeline and is kept
 * byte-identical to the upstream manuscript so it can be re-synced easily. This
 * preprocessor adapts it to mdBook (pulldown-cmark / CommonMark) at build time,
 * without editing the source files. It reproduces what design/lua/trustchain.lua
 * does for the HTML edition, so the web book keeps the print book's look:
 *
 *   1. `::: trust-ledger ... :::`  ->  <div class="trust-ledger"> ... </div>.
 *   2. A blockquote whose first line starts with a provenance emoji
 *      (green/yellow/blue) becomes an evidence certificate:
 *      <div class="evidence evidence-{captured|emulated|documented}">. The code
 *      block that follows is welded to it by CSS (`.evidence-* + pre`).
 *   3. A blockquote whose first line starts with a bold lead-in becomes a named
 *      callout <div class="callout callout-{kind}">, classified exactly like the
 *      Lua filter (definition, insight, aside, note, quote, foundations,
 *      warning, walkthrough) or a figure (<div class="figure-prose">).
 *   4. Image paths `](diagrams/x.svg)` -> `](../diagrams/x.svg)`.
 *   5. Reference-list items `1. [Name]: ...` -> `1. \[Name\]: ...` so a leading
 *      `[label]:` is not consumed as a link-reference definition.
 *
 * The div wrappers use blank-line separation so CommonMark parses the inner
 * Markdown (the same pattern mdBook documents for raw HTML with Markdown inside).
 *
 * Protocol: https://rust-lang.github.io/mdBook/for_developers/preprocessors.html
 */
'use strict';

import katex from 'katex';

const GREEN = '\u{1F7E2}'; // CAPTURED
const YELLOW = '\u{1F7E1}'; // EMULATED
const BLUE = '\u{1F535}'; // DOCUMENTED

// Bold lead-in -> callout kind, mirroring CALLOUT_KIND in trustchain.lua.
const CALLOUT_KIND = {
  'definition': 'definition',
  'key idea': 'insight', 'key takeaway': 'insight', 'takeaway': 'insight',
  'chapter thesis': 'insight', 'thesis': 'insight', 'insight': 'insight',
  'aside': 'aside',
  'quoted source': 'quote', 'quoted anchor': 'quote', 'source quotation': 'quote',
  'primary-source quotation': 'quote', 'primary source quotation': 'quote',
  'quotation': 'quote', 'quote': 'quote',
  'diagram in prose': 'figure',
  'note': 'note', 'sidenote': 'note', 'side note': 'note', 'sidebar': 'note',
  'anti-confusion': 'note', 'evidence note': 'note', 'where this sits': 'note',
  'bequeaths': 'note', 'honest labelling': 'note', 'honest labeling': 'note',
  'foundations': 'foundations',
  'walkthrough': 'walkthrough', 'walk-through': 'walkthrough', 'procedure': 'walkthrough',
  'tip': 'insight', 'how to': 'walkthrough', 'step by step': 'walkthrough',
  'warning': 'warning', 'caution': 'warning', 'pitfall': 'warning', 'gotcha': 'warning',
};
// Longest keys first so "key takeaway" wins over "takeaway".
const CALLOUT_KEYS = Object.keys(CALLOUT_KIND).sort((a, b) => b.length - a.length);

function classify(lead) {
  const low = lead.toLowerCase();
  for (const k of CALLOUT_KEYS) {
    if (low.startsWith(k)) return CALLOUT_KIND[k];
  }
  if (/ is not | are not |isn'?t |aren'?t | vs\.? | versus |not the same|≠/.test(low)) {
    return 'warning';
  }
  return 'note';
}

function evidenceTier(firstLine) {
  const s = firstLine.trimStart();
  if (s.startsWith(GREEN)) return 'captured';
  if (s.startsWith(YELLOW)) return 'emulated';
  if (s.startsWith(BLUE)) return 'documented';
  return null;
}

// Strip leading/trailing blank lines from an array of lines.
function trimBlankLines(lines) {
  let start = 0;
  let end = lines.length;
  while (start < end && lines[start].trim() === '') start++;
  while (end > start && lines[end - 1].trim() === '') end--;
  return lines.slice(start, end);
}

function wrapDiv(classes, innerLines) {
  return ['', `<div class="${classes.join(' ')}">`, '', ...trimBlankLines(innerLines), '', '</div>', ''];
}

// Convert `::: trust-ledger ... :::` fenced divs to HTML div wrappers.
function convertTrustLedger(lines) {
  const out = [];
  let inLedger = false;
  for (const line of lines) {
    if (!inLedger && /^:::\s*trust-ledger\s*$/.test(line)) {
      inLedger = true;
      out.push('', '<div class="trust-ledger">', '');
      continue;
    }
    if (inLedger && /^:::\s*$/.test(line)) {
      inLedger = false;
      out.push('', '</div>', '');
      continue;
    }
    out.push(line);
  }
  return out;
}

// Convert provenance/callout blockquotes to styled divs. Runs a line-level scan
// that skips fenced code blocks and collects contiguous `>` blockquote groups.
function convertBlockquotes(lines) {
  const out = [];
  let i = 0;
  let fence = null; // active top-level code fence marker (``` or ~~~)

  while (i < lines.length) {
    const line = lines[i];

    // Track top-level fenced code so blockquote-looking lines inside are ignored.
    const fenceOpen = line.match(/^\s*(```+|~~~+)/);
    if (fence) {
      out.push(line);
      if (fenceOpen && line.trim().startsWith(fence)) fence = null;
      i++;
      continue;
    }
    if (fenceOpen) {
      fence = fenceOpen[1];
      out.push(line);
      i++;
      continue;
    }

    if (/^>/.test(line)) {
      const group = [];
      while (i < lines.length && /^>/.test(lines[i])) {
        group.push(lines[i]);
        i++;
      }
      const inner = group.map((l) => l.replace(/^>\s?/, ''));
      const firstIdx = inner.findIndex((l) => l.trim() !== '');
      const first = firstIdx >= 0 ? inner[firstIdx] : '';

      const tier = evidenceTier(first);
      if (tier) {
        // Peek past blank lines and any evidence marker: a certificate welds to
        // a following code block; otherwise it stands alone (full rounding).
        let k = i;
        while (k < lines.length && (lines[k].trim() === '' || /^<!--\s*evidence\b/.test(lines[k]))) k++;
        const welded = k < lines.length && /^\s*(```+|~~~+)/.test(lines[k]);
        const classes = ['evidence', `evidence-${tier}`];
        if (!welded) classes.push('evidence-standalone');
        out.push(...wrapDiv(classes, inner));
        continue;
      }
      const bold = first.trimStart().match(/^\*\*(.+?)\*\*/);
      if (bold) {
        const kind = classify(bold[1]);
        const classes = kind === 'figure' ? ['figure-prose'] : ['callout', `callout-${kind}`];
        out.push(...wrapDiv(classes, inner));
        continue;
      }
      // Generic quote: leave as a plain blockquote.
      out.push(...group);
      continue;
    }

    out.push(line);
    i++;
  }
  return out;
}

// Render TeX math to HTML at build time (KaTeX), BEFORE mdBook's CommonMark
// parser can mangle `$...$` (e.g. eat `_` subscripts). Code spans/blocks are
// matched first in the alternation so `$` inside them is never treated as math.
const MATH_RE = new RegExp(
  '(```[\\s\\S]*?```|~~~[\\s\\S]*?~~~|`[^`\\n]*`)' +      // 1: code (protected)
  '|\\$\\$([\\s\\S]+?)\\$\\$' +                            // 2: display math
  '|(?<![\\\\$])\\$(?!\\s)((?:\\\\.|[^$\\\\\\n])+?)(?<!\\s)\\$(?!\\d)', // 3: inline
  'g');

function renderMath(content) {
  return content.replace(MATH_RE, (m, code, disp, inl) => {
    if (code !== undefined) return code; // leave code untouched
    try {
      if (disp !== undefined) {
        const html = katex.renderToString(disp.trim(),
          { displayMode: true, throwOnError: false, output: 'html', strict: false });
        return `\n\n<div class="katex-block">${html}</div>\n\n`;
      }
      return katex.renderToString(inl,
        { displayMode: false, throwOnError: false, output: 'html', strict: false });
    } catch (e) {
      return m; // on any failure, leave the original text
    }
  });
}

function transform(content) {
  content = renderMath(content);
  let lines = content.split('\n');
  lines = convertTrustLedger(lines);
  lines = convertBlockquotes(lines);
  let text = lines.join('\n');

  // Drop build-time evidence markers so the certificate header sits directly
  // adjacent to its code block (`.evidence-* + pre`).
  text = text.replace(/^<!--\s*evidence\b[^>]*-->\s*$/gm, '');

  // Rewrite diagram image paths for the one-level-deep source layout.
  text = text.replace(/\]\(diagrams\//g, '](../diagrams/');
  text = text.replace(/(<img[^>]*\bsrc=")diagrams\//g, '$1../diagrams/');

  // Escape a leading `[label]:` in list items so it is not parsed as a
  // link-reference definition (which renders nothing).
  text = text.replace(/^(\s*(?:\d+\.|[-*])\s+)\[([^\]]+)\]:/gm, '$1\\[$2\\]:');

  return text;
}

function walk(items) {
  for (const item of items) {
    if (item && item.Chapter) {
      const ch = item.Chapter;
      if (typeof ch.content === 'string') ch.content = transform(ch.content);
      if (Array.isArray(ch.sub_items)) walk(ch.sub_items);
    }
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args[0] === 'supports') process.exit(0);

  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { input += chunk; });
  process.stdin.on('end', () => {
    const [, book] = JSON.parse(input);
    walk(book.sections);
    process.stdout.write(JSON.stringify(book));
  });
}

main();
