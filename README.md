# The Windows Trust Chain

**How modern Windows builds an unbroken, verifiable chain of trust from silicon to cloud, and where attackers break it.**

This is the source for an open, evidence-based technical book aimed at security
architects, detection leads, threat modelers, and advanced blue teams. It follows
trust as it is *inherited* link by link, from firmware and the TPM up through the
kernel, credentials, access control, and cloud identity, and it is honest about
where each link breaks.

Where a claim can be checked on a live machine, the book gives the exact command
to reproduce it and, where the output was captured, a cryptographic hash that
proves it was not edited to fit the prose.

> **Read it online:** _(published via GitHub Pages once the repository is public)_

## What is in here

- 30 chapters (a Prologue, a Foundations primer, and 29 numbered chapters)
  grouped into four parts plus an Interlude and a Finale.
- Every chapter opens with a **trust ledger**: what the link inherits, what it
  promises, its trusted computing base, how an adversary breaks it, what residual
  risk remains, and what it bequeaths to the next link.
- A provenance taxonomy tags every piece of evidence:
  - 🟢 **CAPTURED** verbatim, hash-verified output from a lab VM.
  - 🟡 **EMULATED** real values rooted in the host or VM layer.
  - 🔵 **DOCUMENTED** mechanisms shown from primary sources, clearly labeled as
    not captured on the lab VM.

The site is built with [mdBook](https://rust-lang.github.io/mdBook/), the same
engine behind the official Rust book, so it ships with a chapter sidebar,
full-text search, and light and dark themes.

## Read or build locally

You need [mdBook](https://rust-lang.github.io/mdBook/) (0.4.43+) and Node.js
(18+, used by the build-time preprocessor).

```bash
# Install mdBook (prebuilt binary), then:
mdbook serve --open   # live-reload preview at http://localhost:3000
mdbook build          # static site into ./book
```

Deploys additionally run a post-build SEO pass (canonical URLs, Open Graph and
Twitter cards, `schema.org/Book` JSON-LD, `sitemap.xml`, and `robots.txt`):

```bash
SITE_URL=https://maliparag.github.io/windows-trust-chain node tools/gen-seo.mjs
```

If you edit which chapters exist or their order, regenerate the table of
contents:

```bash
node tools/gen-summary.mjs   # rewrites src/SUMMARY.md from the reading order
```

## Repository layout

```text
.
├── src/
│   ├── SUMMARY.md          Table of contents (generated; reading order != file order)
│   ├── front-matter/       Title, copyright, preface, reading guide
│   ├── chapters/           Prologue, Foundations, and 29 numbered chapters
│   ├── back-matter/        References, glossary, about, colophon, index
│   └── diagrams/           SVG figures referenced by the chapters
├── theme/trustchain.css    Styling for the trust-ledger blocks and figures
├── tools/
│   ├── gen-summary.mjs      Regenerates src/SUMMARY.md in canonical reading order
│   ├── mdbook-trustchain.mjs mdBook preprocessor (trust-ledger, callouts, evidence, figures)
│   └── gen-seo.mjs          Post-build SEO: canonical, Open Graph, JSON-LD, sitemap, robots
├── book.toml               mdBook configuration
└── .github/workflows/      Build and deploy to GitHub Pages
```

### About the source Markdown

Chapter Markdown is kept close to the print manuscript so the two stay in sync.
The mdBook preprocessor (`tools/mdbook-trustchain.mjs`) adapts it for the web at
build time (rendering the `::: trust-ledger` blocks, resolving figure paths, and
keeping reference lists intact) without modifying the source files.

## Contributing

Corrections, clarifications, and reproductions are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md). Please keep the house style: the prose is
deliberately free of em-dashes, and verbatim quotes from vendors, researchers,
and standards must stay verbatim.

## License

Everything in this repository, the prose, the diagrams, and the build tooling,
is licensed under
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/)
(CC BY-NC-SA 4.0). See [LICENSE](LICENSE). In short: share and adapt for
noncommercial purposes, with attribution, under the same license. The author
reserves all commercial rights.

Verbatim quotations from vendors, researchers, and standards bodies, and any
trademarks, remain the property of their respective owners and are not covered by
this license. By contributing, you also grant the author a license to use your
contribution in commercial editions; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Author

Written by Parag Mali.
