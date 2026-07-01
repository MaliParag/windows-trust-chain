#!/usr/bin/env node
/**
 * Generate src/SUMMARY.md for mdBook from the canonical reading order of
 * "The Windows Trust Chain".
 *
 * The reading order is NOT the filename order: chapters are interleaved into
 * parts (silicon -> kernel -> credentials -> cloud) and numbered sequentially
 * in that order. The prose's cross-references ("Chapter 6, The Secure Kernel")
 * use these reading-order numbers, so the sidebar MUST match. This structure is
 * the source of truth, mirrored from book/scripts/assemble.mjs upstream.
 *
 * Usage: node tools/gen-summary.mjs
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'src');

// Front matter (unnumbered prefix chapters), in order.
const FRONT = [
  ['front-matter/00-title.md', 'Title Page'],
  ['front-matter/01-copyright.md', 'Copyright'],
  ['front-matter/02-preface.md', 'Preface'],
  ['front-matter/03-how-to-read.md', 'How to Read This Book'],
];

// Unnumbered specials that open the body (still prefix chapters).
const SPECIALS = [
  ['chapters/00-prologue.md', 'Prologue'],
  ['chapters/00b-foundations.md', 'Foundations'],
];

// Numbered body, grouped into parts (reading order == numbering order).
const PARTS = [
  { title: 'Part I · Silicon',
    items: ['16-secure-boot', '01-tpm', '02-pluton', '03-measured-boot', '04-attestation'] },
  { title: 'Part II · Kernel & Code',
    items: ['05-secure-kernel', '17-vbs-trustlets', '06-code-integrity', '07-hypervisor', '18-ppl', '19-mitigations', '20-authenticode', '21-app-control'] },
  { title: 'Part III · Credentials & Access',
    items: ['22-mimikatz', '08-credential-guard', '09-ntlm', '10-kerberos', '23-krbtgt', '11-pth-prt', '12-hello', '24-webauthn', '25-access-control', '26-integrity-levels', '27-seimpersonate'] },
  { title: 'Interlude · Watching the Chain',
    items: ['28-etw'] },
  { title: 'Part IV · Cloud',
    items: ['13-zero-trust', '14-cae', '29-confidential-vms'] },
  { title: 'Finale · When the Chain Snaps',
    items: ['15-storm0558'] },
];

// Back matter (unnumbered suffix chapters), in order.
const BACK = [
  'back-matter/70-references.md',
  'back-matter/80-glossary.md',
  'back-matter/85-about.md',
  'back-matter/90-colophon.md',
  'back-matter/95-index.md',
];

function h1(relPath) {
  const p = path.join(SRC, relPath);
  if (!existsSync(p)) throw new Error(`missing source file: ${relPath}`);
  const line = readFileSync(p, 'utf8').split(/\r?\n/).find((l) => /^#\s+/.test(l)) || '# Untitled';
  // Strip a leading "Chapter N · " / "Prologue" / "Foundations" decoration.
  return line.replace(/^#\s+/, '')
    .replace(/^(Chapter\s+\d+[A-Za-z]*|Prologue|Foundations)\s*[·:\-]\s*/i, '')
    .trim();
}

const out = ['# Summary', ''];

// Prefix chapters: front matter, then the two unnumbered openers.
for (const [rel, label] of FRONT) out.push(`[${label}](${rel})`);
for (const [rel, label] of SPECIALS) out.push(`[${label}](${rel})`);
out.push('');

// Numbered parts.
for (const part of PARTS) {
  out.push(`# ${part.title}`, '');
  for (const slug of part.items) {
    const rel = `chapters/${slug}.md`;
    out.push(`- [${h1(rel)}](${rel})`);
  }
  out.push('');
}

// Suffix chapters: back matter.
out.push('---', '');
for (const rel of BACK) out.push(`[${h1(rel)}](${rel})`);
out.push('');

writeFileSync(path.join(SRC, 'SUMMARY.md'), out.join('\n'), 'utf8');
console.log('wrote src/SUMMARY.md');
