#!/usr/bin/env node
/**
 * mdBook preprocessor for "The Windows Trust Chain".
 *
 * The book's Markdown is authored for a Pandoc+Typst print pipeline and is kept
 * byte-identical to the upstream manuscript so it can be re-synced easily. This
 * preprocessor adapts it to mdBook (pulldown-cmark / CommonMark) at build time,
 * without editing the source files:
 *
 *   1. `::: trust-ledger ... :::`  ->  a styled <div class="trust-ledger"> block
 *      (Pandoc fenced_div syntax that CommonMark does not understand).
 *   2. Image paths `](diagrams/x.svg)` -> `](../diagrams/x.svg)` so figures in
 *      src/{chapters,front-matter,back-matter}/ resolve to src/diagrams/.
 *   3. Reference-list items `1. [Name]: ...` -> `1. \[Name\]: ...` so a leading
 *      `[label]:` is not silently consumed as a link-reference definition.
 *
 * Protocol: https://rust-lang.github.io/mdBook/for_developers/preprocessors.html
 *   `<cmd> supports <renderer>`  -> exit 0 if supported.
 *   otherwise: read [context, book] JSON on stdin, write the book JSON on stdout.
 */
'use strict';

function transform(content) {
  // 1. Pandoc fenced div `::: trust-ledger` -> HTML div wrapping Markdown.
  //    Blank lines around the tags let CommonMark render the inner Markdown.
  const lines = content.split('\n');
  const out = [];
  let inLedger = false;
  for (const line of lines) {
    if (!inLedger && /^:::\s*trust-ledger\s*$/.test(line)) {
      inLedger = true;
      out.push('<div class="trust-ledger">', '');
      continue;
    }
    if (inLedger && /^:::\s*$/.test(line)) {
      inLedger = false;
      out.push('', '</div>');
      continue;
    }
    out.push(line);
  }
  let text = out.join('\n');

  // 2. Rewrite diagram image paths for the one-level-deep source layout.
  text = text.replace(/\]\(diagrams\//g, '](../diagrams/');
  text = text.replace(/(<img[^>]*\bsrc=")diagrams\//g, '$1../diagrams/');

  // 3. Escape a leading `[label]:` in ordered/unordered list items so it is not
  //    parsed as a link-reference definition (which renders nothing).
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
  if (args[0] === 'supports') {
    // Support every renderer; transforms are renderer-agnostic HTML/Markdown.
    process.exit(0);
  }

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
