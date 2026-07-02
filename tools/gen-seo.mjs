#!/usr/bin/env node
/**
 * Post-build SEO pass for the mdBook output of "The Windows Trust Chain".
 *
 * mdBook emits a <title> and description per page but no canonical URL, social
 * cards, structured data, sitemap, or robots file. Handlebars cannot compute a
 * page's absolute URL, so this runs after `mdbook build` (locally and in CI) and
 * injects, per page:
 *   - <link rel="canonical"> (self-referencing, avoids duplicate-content issues)
 *   - Open Graph + Twitter card tags (rich link previews)
 *   - schema.org/Book JSON-LD (so search engines understand this is a book)
 * and writes sitemap.xml + robots.txt at the site root. The print page is marked
 * noindex so it does not compete with the real chapters.
 *
 * Base URL comes from $SITE_URL, else the GitHub Pages project URL.
 *
 * Usage: SITE_URL=https://host/path node tools/gen-seo.mjs [book-dir]
 */
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BOOK_DIR = path.resolve(ROOT, process.argv[2] || 'book');
const BASE = (process.env.SITE_URL || 'https://maliparag.github.io/windows-trust-chain').replace(/\/+$/, '');

const TITLE = 'The Windows Trust Chain';
const SUBTITLE = 'How Modern Windows Builds Trust from Silicon to Cloud, and Where Attackers Break It';
const AUTHOR = 'Parag Mali';
const DESCRIPTION = 'How modern Windows builds a verifiable chain of trust from silicon to cloud, and where attackers break it. An open, evidence-based technical book.';
const LICENSE = 'https://creativecommons.org/licenses/by-nc-sa/4.0/';
const IMAGE = existsSync(path.join(BOOK_DIR, 'cover.png')) ? `${BASE}/cover.png` : null;
const IMAGE_W = 1400;
const IMAGE_H = 1850;

const SKIP = new Set(['404.html', 'toc.html']); // fragments / non-indexable helpers

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
// Extract already-escaped inner content, then normalize for attribute reuse.
function attr(s) {
  return s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
}

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walk(p));
    else if (name.endsWith('.html')) out.push(p);
  }
  return out;
}

const bookSchema = JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'Book',
  name: TITLE,
  alternateName: `${TITLE}: ${SUBTITLE}`,
  headline: SUBTITLE,
  author: { '@type': 'Person', name: AUTHOR },
  publisher: { '@type': 'Person', name: AUTHOR },
  inLanguage: 'en',
  bookFormat: 'https://schema.org/EBook',
  genre: 'Computer security',
  url: `${BASE}/`,
  description: DESCRIPTION,
  license: LICENSE,
  ...(IMAGE ? { image: IMAGE } : {}),
});

const pages = [];

for (const file of walk(BOOK_DIR)) {
  const rel = path.relative(BOOK_DIR, file).split(path.sep).join('/');
  const base = path.basename(file);
  if (SKIP.has(rel)) continue;

  let html = readFileSync(file, 'utf8');
  if (!html.includes('</head>')) continue;
  if (html.includes('data-seo="1"')) continue; // idempotent

  const isRoot = rel === 'index.html';
  const isPrint = rel === 'print.html';
  const url = isRoot ? `${BASE}/` : `${BASE}/${rel}`;

  const titleMatch = html.match(/<title>([\s\S]*?)<\/title>/i);
  let pageTitle = titleMatch ? attr(titleMatch[1].trim()) : TITLE;
  const descMatch = html.match(/<meta name="description" content="([^"]*)"/i);
  const pageDesc = descMatch ? attr(descMatch[1]) : DESCRIPTION;

  // Give the landing page a descriptive, keyword-rich title.
  if (isRoot) {
    const full = `${TITLE}: ${SUBTITLE}`;
    html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${esc(full)}</title>`);
    pageTitle = full;
  }

  const tags = [];
  tags.push(`<meta data-seo="1" property="og:type" content="${isRoot ? 'book' : 'article'}">`);
  tags.push(`<meta property="og:site_name" content="${esc(TITLE)}">`);
  tags.push(`<meta property="og:title" content="${esc(pageTitle)}">`);
  tags.push(`<meta property="og:description" content="${esc(pageDesc)}">`);
  tags.push(`<meta property="og:url" content="${esc(url)}">`);
  tags.push(`<meta property="og:locale" content="en_US">`);
  if (IMAGE) {
    tags.push(`<meta property="og:image" content="${esc(IMAGE)}">`);
    tags.push(`<meta property="og:image:width" content="${IMAGE_W}">`);
    tags.push(`<meta property="og:image:height" content="${IMAGE_H}">`);
    tags.push(`<meta property="og:image:alt" content="${esc(TITLE)} book cover">`);
  }
  tags.push(`<meta name="twitter:card" content="${IMAGE ? 'summary_large_image' : 'summary'}">`);
  tags.push(`<meta name="twitter:title" content="${esc(pageTitle)}">`);
  tags.push(`<meta name="twitter:description" content="${esc(pageDesc)}">`);
  if (IMAGE) tags.push(`<meta name="twitter:image" content="${esc(IMAGE)}">`);
  tags.push(`<meta name="author" content="${esc(AUTHOR)}">`);

  if (isPrint) {
    if (!/name="robots"/i.test(html)) tags.push('<meta name="robots" content="noindex, follow">');
  } else {
    tags.push(`<link rel="canonical" href="${esc(url)}">`);
    pages.push(url);
  }

  if (isRoot || base.startsWith('0') || /chapters\//.test(rel)) {
    tags.push(`<script type="application/ld+json">${bookSchema}</script>`);
  }

  html = html.replace('</head>', `        ${tags.join('\n        ')}\n    </head>`);
  writeFileSync(file, html, 'utf8');
}

// Sitemap (indexable pages only), homepage first.
pages.sort((a, b) => (a === `${BASE}/` ? -1 : b === `${BASE}/` ? 1 : a.localeCompare(b)));
const today = new Date().toISOString().slice(0, 10);
const sitemap = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  ...pages.map((u) => `  <url><loc>${u}</loc><lastmod>${today}</lastmod></url>`),
  '</urlset>',
  '',
].join('\n');
writeFileSync(path.join(BOOK_DIR, 'sitemap.xml'), sitemap, 'utf8');

const robots = [
  'User-agent: *',
  'Allow: /',
  '',
  `Sitemap: ${BASE}/sitemap.xml`,
  '',
].join('\n');
writeFileSync(path.join(BOOK_DIR, 'robots.txt'), robots, 'utf8');

console.log(`SEO: injected tags into ${pages.length + 1} pages; wrote sitemap.xml (${pages.length} urls) + robots.txt; base=${BASE}`);
