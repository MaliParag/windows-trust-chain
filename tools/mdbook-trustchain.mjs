#!/usr/bin/env node
/**
 * mdBook preprocessor for "The Windows Trust Chain".
 *
 * The book's Markdown is authored for a Pandoc+Typst print pipeline and is kept
 * byte-identical to the upstream manuscript so it can be re-synced easily. This
 * preprocessor reproduces, for mdBook (pulldown-cmark / CommonMark), the same
 * designed components the print/HTML build emits from design/lua/trustchain.lua,
 * without editing the source files:
 *
 *   1. `::: trust-ledger ... :::`            -> <div class="trust-ledger">
 *   2. Blockquotes led by an emoji tier
 *      `> 🟢/🟡/🔵 **CAPTURED/...**`          -> <div class="evidence evidence-TIER">
 *      (the following code block is welded to it by theme/trustchain.css).
 *   3. Blockquotes led by a bold label
 *      `> **Key idea.** ...`                 -> <div class="callout callout-KIND">
 *      classified with the same label->kind map as the print build.
 *   4. Image paths `](diagrams/x.svg)`       -> `](../diagrams/x.svg)`
 *   5. Reference-list items `1. [Name]: ..`  -> `1. \[Name\]: ..` (keep visible).
 *
 * Protocol: https://rust-lang.github.io/mdBook/for_developers/preprocessors.html
 */
'use strict';

// label (lowercased prefix) -> callout kind. Mirrors CALLOUT_KIND in
// design/lua/trustchain.lua. Longest keys are matched first.
const CALLOUT_KIND = {
  'definition': 'definition',
  'key idea': 'insight', 'key takeaway': 'insight', 'takeaway': 'insight',
  'chapter thesis': 'insight', 'thesis': 'insight', 'insight': 'insight',
  'aside': 'aside',
  'quoted source': 'quote', 'quoted anchor': 'quote', 'source quotation': 'quote',
  'primary-source quotation': 'quote', 'primary source quotation': 'quote',
  'quotation': 'quote', 'quote': 'quote', 'pull quote': 'quote',
  'diagram in prose': 'figure',
  'note': 'note', 'sidenote': 'note', 'side note': 'note', 'sidebar': 'note',
  'margin note': 'note', 'source note': 'note', 'anti-confusion': 'note',
  'evidence note': 'note', 'evidence labels': 'note', 'where this sits': 'note',
  'bequeaths': 'note', 'honest labelling': 'note', 'honest labeling': 'note',
  'foundations': 'foundations',
  'tip': 'insight', 'how to': 'walkthrough', 'step by step': 'walkthrough',
  'warning': 'warning', 'caution': 'warning', 'pitfall': 'warning', 'gotcha': 'warning',
};
const CALLOUT_KEYS = Object.keys(CALLOUT_KIND).sort((a, b) => b.length - a.length);

const TIER = { '🟢': 'captured', '🟡': 'emulated', '🔵': 'documented' };

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

// Wrap a run of blockquote lines. `original` is the untouched `>`-prefixed run;
// `inner` is the same run with the leading `> ` stripped.
function wrapBlockquote(original, inner) {
  const firstIdx = inner.findIndex((l) => l.trim() !== '');
  if (firstIdx < 0) return original;
  const first = inner[firstIdx].trim();

  for (const [emoji, tier] of Object.entries(TIER)) {
    if (first.startsWith(emoji)) {
      return [`<div class="evidence evidence-${tier}">`, '', ...inner, '', '</div>'];
    }
  }

  const m = first.match(/^\*\*(.+?)\*\*/);
  if (m) {
    const kind = classify(m[1]);
    const cls = kind === 'figure' ? 'figure-prose' : `callout callout-${kind}`;
    return [`<div class="${cls}">`, '', ...inner, '', '</div>'];
  }

  return original; // generic blockquote, leave as-is
}

function transform(content) {
  const lines = content.split('\n');
  const out = [];
  let i = 0;
  let inCode = false;
  let fence = '';

  while (i < lines.length) {
    const line = lines[i];
    const fenceOpen = line.match(/^\s*(```+|~~~+)/);

    if (inCode) {
      out.push(line);
      if (fenceOpen && line.trim().startsWith(fence)) { inCode = false; fence = ''; }
      i++;
      continue;
    }
    if (fenceOpen) {
      inCode = true;
      fence = fenceOpen[1];
      out.push(line);
      i++;
      continue;
    }

    // A `::: trust-ledger` fenced div (Pandoc) -> styled HTML div.
    if (/^:::\s*trust-ledger\s*$/.test(line)) {
      out.push('<div class="trust-ledger">', '');
      i++;
      while (i < lines.length && !/^:::\s*$/.test(lines[i])) { out.push(lines[i]); i++; }
      i++; // skip closing :::
      out.push('', '</div>');
      continue;
    }

    // A blockquote run (contiguous `>`-prefixed lines).
    if (/^>/.test(line)) {
      const original = [];
      while (i < lines.length && /^>/.test(lines[i])) { original.push(lines[i]); i++; }
      const inner = original.map((l) => l.replace(/^>\s?/, ''));
      out.push(...wrapBlockquote(original, inner));
      continue;
    }

    out.push(line);
    i++;
  }

  let text = out.join('\n');

  // Rewrite diagram image paths for the one-level-deep source layout.
  text = text.replace(/\]\(diagrams\//g, '](../diagrams/');
  text = text.replace(/(<img[^>]*\bsrc=")diagrams\//g, '$1../diagrams/');

  // Escape a leading `[label]:` in list items so it is not parsed as a link
  // reference definition (which renders nothing).
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
